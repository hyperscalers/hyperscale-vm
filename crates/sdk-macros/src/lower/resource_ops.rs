//! The calling surface of an issued mark: what `Name::mint(..)`,
//! `Name::burn(..)`, the record and instance operations, `recall`,
//! `halt` and `destroy` lower to.
//!
//! Leaves of the one walk, not a walk of their own: the parent
//! dispatches here when a call names a resource the package issues, and
//! each operation reads the declaration's resource, asks for the grant
//! the method's outputs earn, and hands back the produced edge as an
//! [`Eval`].

use hyperscale_vm_effects::vocabulary::{CONFIG, HALT, INSTANCE, RESOURCE};
use hyperscale_vm_effects::{GrantedBehaviour, Issued, ResourceKind};
use proc_macro2::Span;
use quote::quote;
use syn::spanned::Spanned;

use super::{Code, Eval, Form, Lowerer, Need, Target, Val, borrowed, capitalized, is_nf_bucket};
use crate::resource::Resource;
use crate::term::{Op, SlotRef, Term};

impl Lowerer<'_> {
    /// Lower `Name::mint(quantity)` — value with no cell debited behind
    /// it, against the grant this method's declared outputs earn.
    pub(super) fn lower_mint(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        let amount = call.args.first().map_or(
            Code::Absent(call.args.span(), "an issue with no amount"),
            |a| self.expr(a).code,
        );
        let amount = self.value(amount);
        let grant = self.issuer(ResourceKind::Fungible, &issued.mark, Issued::Minted);
        Eval {
            val: Val::Produced(Term::SelfResource(
                ResourceKind::Fungible,
                issued.mark.clone(),
            )),
            code: Code::Rust(quote!(::hyperscale_vm_sdk::state::mint_granted(#grant, #amount))),
        }
    }

    /// Lower `Name::__record(..)` — the record cell, under the one-way
    /// door its absence is.
    ///
    /// The record is the protocol's own encoding rather than anything a
    /// body assembles, so what the call carries is the single fact the
    /// address does not: a fungible resource's display quantization,
    /// which the mark's own attribute states.
    pub(super) fn lower_record_create(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        let stated: Vec<_> = call
            .args
            .iter()
            .map(|arg| {
                let eval = self.expr(arg);
                self.value(eval.code)
            })
            .collect();
        let record = match issued.kind {
            ResourceKind::Fungible => {
                let Some(display_digits) = stated.first() else {
                    self.error(
                        call.span(),
                        "a fungible record states its display quantization: \
                         `create(<display_digits>)`",
                    );
                    return Eval::absent(call.span(), "a record with no display width");
                };
                quote!(::hyperscale_vm_sdk::state::ResourceRecord::Fungible {
                    display_digits: #display_digits,
                })
            }
            ResourceKind::NonFungible => {
                if !stated.is_empty() {
                    self.error(
                        call.span(),
                        "a non-fungible record has nothing to state — the kind is the \
                         mark's and instances are whole by construction",
                    );
                }
                quote!(::hyperscale_vm_sdk::state::ResourceRecord::NonFungible)
            }
        };
        let site = self.open(
            Target::Point {
                owner: None,
                slot: SlotRef::Fixed(RESOURCE.0),
                material: vec![Term::SelfResource(issued.kind, issued.mark.clone())],
            },
            Some(syn::parse_quote!(
                ::core::option::Option<::hyperscale_vm_sdk::state::ResourceRecord>
            )),
            None,
        );
        self.record(site, Op::Create, None, call.span());
        let leaf = self.value(Code::Handle {
            site,
            form: Form::Slot,
            span: call.span(),
        });
        Eval::plain(quote!(#leaf.create(#record)))
    }

    /// Lower the generated `instantiate` body's one statement: the
    /// creation-fixed record sealed into the configuration leaf, under
    /// the one-way door its absence is.
    ///
    /// The bytes are the kernel's evaluation of the record admission
    /// resolved the target with, handed over as a value the body cannot
    /// choose — so what the leaf ends holding is what the address
    /// commits, or the transaction never admitted.
    pub(super) fn seal_record(&mut self, call: &syn::ExprMethodCall) -> Eval {
        let site = self.open(
            Target::Point {
                owner: None,
                slot: SlotRef::Fixed(CONFIG.0),
                material: vec![],
            },
            Some(syn::parse_quote!(::std::vec::Vec<u8>)),
            None,
        );
        self.record(site, Op::Create, None, call.span());
        let leaf = self.value(Code::Handle {
            site,
            form: Form::Slot,
            span: call.span(),
        });
        let record = self.need(call.span(), &Need::Derived(Term::SelfRecord));
        Eval::plain(quote!(#leaf.set(#record)))
    }

    /// Lower `Name::at(id)` — the record one instance carries, read at
    /// the cell its mint filed it in.
    ///
    /// Issuer-side by construction rather than by rule: the mark is the
    /// package's own type, so there is no spelling for a foreign
    /// instance's data, and reaching one is a call to whoever issues it.
    pub(super) fn lower_at(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        if let Some(refused) = self.instance_record(issued, "read", call.func.span()) {
            return refused;
        }
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "an instance is read at its id, and the id is part of the declaration",
            );
            return Eval::absent(call.args.span(), "an instance read with no id");
        };
        let eval = self.expr(named);
        let Val::Term(id) = eval.val else {
            self.error(
                named.span(),
                "this id is not derivable from the method's arguments — routing \
                 evaluates the declaration before execution and never reads state",
            );
            return Eval::absent(named.span(), "an underivable instance id");
        };
        let site = self.instance_site(issued, id, call.func.span());
        self.record(site, Op::Get, None, call.span());
        let leaf = self.value(Code::Handle {
            site,
            form: Form::Slot,
            span: call.span(),
        });
        Eval::plain(quote!(#leaf.get()))
    }

    /// Whether the mark has an instance record at all, refusing on the
    /// mark's own terms where it has none.
    ///
    /// A fungible mark holds a balance and no instance; a non-fungible
    /// one declaring no fields holds the presence byte, which is nothing
    /// to hand back and nothing to change.
    fn instance_record(&mut self, issued: &Resource, what: &str, span: Span) -> Option<Eval> {
        if issued.kind != ResourceKind::NonFungible {
            self.error(
                span,
                &format!(
                    "`{}` is fungible, and value carries no record of its own — a \
                     balance is what it holds and an instance is what has data",
                    issued.name
                ),
            );
            return Some(Eval::absent(span, "a fungible instance record"));
        }
        if !issued.schema {
            self.error(
                span,
                &format!(
                    "`{}` declares no fields, so its instance holds the presence byte \
                     and there is nothing to {what} — a mark carrying a schema is a \
                     struct with fields",
                    issued.name
                ),
            );
            return Some(Eval::absent(span, "a bare instance record"));
        }
        None
    }

    /// Lower `Name::held(edge)` — the record of the one instance the
    /// edge carries, read without the caller naming an id.
    ///
    /// The edge already knows its instances, so the id comes off it
    /// rather than from an argument beside it. Where the edge carries
    /// the caller's instances that is a question the declaration asks at
    /// evaluation, and an edge carrying any other number than one is
    /// refused there, before the body runs.
    pub(super) fn lower_held(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        if let Some(refused) = self.instance_record(issued, "read", call.func.span()) {
            return refused;
        }
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "an instance is read off the edge carrying it, and the edge is part \
                 of the declaration",
            );
            return Eval::absent(call.args.span(), "an instance read with no edge");
        };
        let Some((edge, _)) = self.instance_edge(issued, named, "reads", call.span()) else {
            return Eval::absent(named.span(), "an underivable edge");
        };
        let Some(id) = self.sole_id(edge, named) else {
            return Eval::absent(named.span(), "an edge naming no one instance");
        };
        let site = self.instance_site(issued, id, call.func.span());
        self.record(site, Op::Get, None, call.span());
        let leaf = self.value(Code::Handle {
            site,
            form: Form::Slot,
            span: call.span(),
        });
        Eval::plain(quote!(#leaf.get()))
    }

    /// Lower `Name::each(edge)` — the record of every instance an edge
    /// carries, read without the caller naming an id.
    ///
    /// [`Lowerer::lower_held`]'s general form. What the two cost differs
    /// with what they read: a singleton is one evaluation and one
    /// capability, and this is a clause per instance and the site over
    /// them — so a body that knows it holds one keeps saying so.
    pub(super) fn lower_each(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        if let Some(refused) = self.instance_record(issued, "read", call.func.span()) {
            return refused;
        }
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "the instances are read off the edge carrying them, and the edge is \
                 part of the declaration",
            );
            return Eval::absent(call.args.span(), "an instance read with no edge");
        };
        let Some((edge, _)) = self.instance_edge(issued, named, "reads", call.span()) else {
            return Eval::absent(named.span(), "an underivable edge");
        };
        let issued = issued.clone();
        let span = call.func.span();
        let walk = self.over_instances(edge, span, |me, id| {
            let site = me.instance_site(&issued, id, span);
            me.record(site, Op::Get, None, span);
            let leaf = me.value(Code::Handle {
                site,
                form: Form::Slot,
                span,
            });
            // A live instance's cell holds its record, so the absence a
            // retired one would leave is the one thing there is nothing
            // to collect for.
            quote!(__records.extend(#leaf.get());)
        });
        Eval::plain(quote!({
            let mut __records = ::std::vec::Vec::new();
            #walk
            __records
        }))
    }

    /// Lower `Name::rewrite(id, record)` — the cell the mint filed,
    /// written again.
    ///
    /// The mint's door read the other way: the leaf is required present
    /// rather than absent, so a rewrite of an id nothing minted, or of
    /// one a burn retired, is refused before the body runs. Issuer-side
    /// by construction, on the terms the read is: the mark is the
    /// package's own type, and the cell sits under the package's own
    /// prefix.
    pub(super) fn lower_rewrite(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        if let Some(refused) = self.instance_record(issued, "change", call.func.span()) {
            return refused;
        }
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "an instance is rewritten at its id, and the id is part of the declaration",
            );
            return Eval::absent(call.args.span(), "a rewrite with no id");
        };
        let eval = self.expr(named);
        let Val::Term(id) = eval.val else {
            self.error(
                named.span(),
                "this id is not derivable from the method's arguments — routing \
                 evaluates the declaration before execution and never reads state",
            );
            return Eval::absent(named.span(), "an underivable instance id");
        };
        let Some(filed) = call.args.iter().nth(1) else {
            self.error(
                call.args.span(),
                &format!(
                    "a rewrite files the whole record: `{}` is what one of its \
                     instances holds, and what replaces it is another",
                    issued.name
                ),
            );
            return Eval::absent(call.args.span(), "a rewrite with no record");
        };
        // The record is the cell's content and not its key, so it is
        // ordinary code the body computes — the declaration is keyed by
        // the id alone, exactly as the mint's is.
        let record = self.expr(filed);
        let record = self.value(record.code);
        let site = self.instance_site(issued, id, call.func.span());
        self.record(site, Op::Existing, None, call.span());
        let leaf = self.value(Code::Handle {
            site,
            form: Form::Slot,
            span: call.span(),
        });
        Eval::plain(quote!(#leaf.rewrite(#record)))
    }

    /// The edge an instance operation is called on, held to the mark's
    /// own resource.
    ///
    /// Walked for the term it names rather than for a value: an
    /// operation keyed by the edge's instances reads nothing off the
    /// handle, and binding one would hand the guest a parameter nothing
    /// touches. Where the edge is a parameter, which resource it carries
    /// is the caller's to supply and the mark's is stated on the
    /// parameter; where the body produced it, the resource is already
    /// fixed and a mismatch is the body naming a mark it did not.
    fn instance_edge(
        &mut self,
        issued: &Resource,
        named: &syn::Expr,
        verb: &str,
        span: Span,
    ) -> Option<(Term, Code)> {
        let eval = self.expr(borrowed(named));
        let carried = Term::SelfResource(ResourceKind::NonFungible, issued.mark.clone());
        let amount = |lowering: &mut Self| {
            lowering.error(
                named.span(),
                &format!(
                    "this edge carries an amount, and an instance of `{}` is what the \
                     call is about — a non-fungible edge is an `NfBucket`, which names \
                     the instances it moves",
                    issued.name
                ),
            );
        };
        match (&eval.val, &eval.code) {
            (Val::Term(edge), Code::Bucket(_, param)) => {
                if !self
                    .params
                    .get(*param as usize)
                    .is_some_and(|(_, ty)| is_nf_bucket(ty))
                {
                    amount(self);
                    return None;
                }
                self.denominate(*param, carried, span);
                Some((edge.clone(), eval.code.clone()))
            }
            (Val::Produced(edge @ Term::NfBucket { resource, .. }), _) => {
                if **resource != carried {
                    let (found, wanted) = (self.describe(resource), self.describe(&carried));
                    self.error(
                        named.span(),
                        &format!(
                            "this {verb} an instance of {wanted} off an edge carrying \
                             {found}. An instance's record is filed under the resource it \
                             is an instance of"
                        ),
                    );
                }
                Some((edge.clone(), eval.code.clone()))
            }
            (Val::Produced(_), _) => {
                amount(self);
                None
            }
            _ => {
                self.error(
                    named.span(),
                    &format!(
                        "the lowering cannot see what this edge carries. {} an instance \
                         off an edge the method was handed or one it minted",
                        capitalized(verb),
                    ),
                );
                None
            }
        }
    }

    /// The id of the one instance an edge carries.
    ///
    /// An edge the body produced names its instances outright, so the id
    /// is the one it names and the cell is the same site the mint
    /// opened — which is what lets a mint and a retirement of the same
    /// instance meet on one leaf rather than on two spellings of it. An
    /// edge whose instances are the caller's names them only at
    /// evaluation, so the id is the sole element of its id list and an
    /// edge carrying any other number is refused there.
    fn sole_id(&mut self, edge: Term, named: &syn::Expr) -> Option<Term> {
        match Self::named_ids(&edge) {
            Some([one]) => Some(one.clone()),
            Some(several) => {
                self.error(
                    named.span(),
                    &format!(
                        "this edge carries {} instances the body named itself, and an \
                         instance is what the call is about — the cells are already this \
                         method's own sites, so each of them is reached at its own id",
                        several.len(),
                    ),
                );
                None
            }
            None => Some(Term::Only(Box::new(Term::IdsOf(Box::new(edge))))),
        }
    }

    /// The instances an edge names outright, where it names them.
    ///
    /// An edge the body produced knows its own ids, so a call about it
    /// reaches the very sites the mint opened. An edge whose instances
    /// are the caller's names them only at evaluation, which is what
    /// makes its width the instance's rather than the signature's.
    fn named_ids(edge: &Term) -> Option<&[Term]> {
        let Term::NfBucket { ids, .. } = edge else {
            return None;
        };
        match ids.as_ref() {
            Term::List(named) => Some(named),
            _ => None,
        }
    }

    /// Lower `Name::burn(edge)` on a non-fungible mark — the instances
    /// the edge carries leave circulation, and the cell each of them
    /// filed ends with them.
    ///
    /// The one instance the edge carries, on the terms the read takes
    /// it: clearing the cells of several would need a site no export
    /// parameter holds. The cell is required present, which is
    /// the mint's own door read the other way round — so a burn of an
    /// instance nothing minted is refused before the body runs, and a
    /// burn of one this body minted is refused where it is written.
    pub(super) fn lower_burn_nf(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "a non-fungible burn retires the instances an edge carries, and the \
                 edge is what it takes",
            );
            return Eval::absent(call.args.span(), "a burn with no edge");
        };
        let Some((edge, destroyed)) = self.instance_edge(issued, named, "retires", call.span())
        else {
            return Eval::absent(named.span(), "an underivable edge");
        };
        // An edge whose ids the body named reaches the very cells its
        // mints opened, so those stay one clause each. An edge whose
        // instances are the caller's is as wide as the caller made it,
        // and every cell it retires is cleared — a retirement that
        // ended one of three would leave two cells describing instances
        // that no longer exist.
        let cleared = if Self::named_ids(&edge).is_some() {
            let Some(id) = self.sole_id(edge, named) else {
                return Eval::absent(named.span(), "an edge naming no one instance");
            };
            let site = self.instance_site(issued, id, call.func.span());
            self.record(site, Op::Existing, None, call.span());
            let handle = self.handle(site, call.span());
            quote!(::hyperscale_vm_sdk::state::clear_instance(#handle);)
        } else {
            let issued = issued.clone();
            let span = call.func.span();
            self.over_instances(edge, span, |me, id| {
                let site = me.instance_site(&issued, id, span);
                me.record(site, Op::Existing, None, span);
                let handle = me.handle(site, span);
                quote!(::hyperscale_vm_sdk::state::clear_instance(#handle);)
            })
        };
        let funds = self.value(destroyed);
        self.issuer(ResourceKind::NonFungible, &issued.mark, Issued::Burned);
        // A burn names no grant: the edge carries the resource it holds,
        // and a mark names one grant, so at most one of the invocation's
        // can be the edge's.
        Eval::plain(quote!({
            #cleared
            ::hyperscale_vm_sdk::state::burn_nf_granted(#funds)
        }))
    }

    /// The data cell of one instance, as every call that reaches it
    /// opens it.
    ///
    /// A site is what its target names, and its element type is settled
    /// where it is first opened — so a mint and a read that opened the
    /// same cell separately would leave whichever came second reading
    /// the other's answer. One opener is what makes the element the
    /// mark's own statement: a fielded mark's cell holds the record it
    /// declares, a bare mark's holds the presence byte and no type.
    fn instance_site(&mut self, issued: &Resource, id: Term, span: Span) -> usize {
        let mark = syn::Ident::new(&issued.name, span);
        let element = issued
            .schema
            .then(|| syn::parse_quote!(::core::option::Option<#mark>));
        self.open(
            Target::Point {
                owner: None,
                slot: SlotRef::Fixed(INSTANCE.0),
                material: vec![
                    Term::SelfResource(ResourceKind::NonFungible, issued.mark.clone()),
                    id,
                ],
            },
            element,
            None,
        )
    }

    /// Lower `Name::mint(id)` — the non-fungible mint, coupled to the
    /// instance-cell write it implies: the named id is one data cell
    /// created where absent, so a minted instance and its filed cell are
    /// one declaration.
    pub(super) fn lower_mint_nf(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "a non-fungible mint names the instance it creates rather than an amount \
                 — one id, and the instance's data cell is keyed by it",
            );
            return Eval::absent(call.args.span(), "a mint with no id");
        };
        let eval = self.expr(named);
        let Val::Term(id) = eval.val else {
            self.error(
                named.span(),
                "this id is not derivable from the method's arguments — routing \
                 evaluates the declaration before execution and never reads state",
            );
            return Eval::absent(named.span(), "an underivable instance id");
        };
        // The data is the cell's content and not its key, so it is
        // ordinary code the body computes — nothing about it reaches the
        // declaration, which is keyed by the id alone.
        let data = match (issued.schema, call.args.iter().nth(1)) {
            (true, Some(arg)) => {
                let eval = self.expr(arg);
                Some(self.value(eval.code))
            }
            (true, None) => {
                self.error(
                    call.args.span(),
                    &format!(
                        "`{}` declares fields, so its instance carries them: a mint names \
                         the id and the record filed under it",
                        issued.name
                    ),
                );
                return Eval::absent(call.args.span(), "a fielded mint with no record");
            }
            (false, Some(arg)) => {
                self.error(
                    arg.span(),
                    &format!(
                        "`{}` declares no fields, so its instance holds the presence byte \
                         and nothing else — a mark carrying a schema is a struct with fields",
                        issued.name
                    ),
                );
                return Eval::absent(arg.span(), "a bare mint handed a record");
            }
            (false, None) => None,
        };
        let resource_term = Term::SelfResource(ResourceKind::NonFungible, issued.mark.clone());
        let site = self.instance_site(issued, id.clone(), call.func.span());
        self.record(site, Op::Create, None, call.span());
        // A fielded mark's cell is the mark's own record, so the mint
        // writes it as one — the same leaf, at the same absence
        // requirement, that a read of this instance reaches. A bare mark
        // has the presence byte and no element type to write it through.
        let file = if let Some(data) = data {
            let leaf = self.value(Code::Handle {
                site,
                form: Form::Slot,
                span: call.span(),
            });
            quote!(#leaf.create(#data);)
        } else {
            let handle = self.handle(site, call.span());
            quote!(::hyperscale_vm_sdk::state::file_instance(#handle);)
        };
        let id_value = self.value(eval.code);
        let grant = self.issuer(ResourceKind::NonFungible, &issued.mark, Issued::Minted);
        let produced = Term::NfBucket {
            resource: Box::new(resource_term),
            ids: Box::new(Term::List(vec![id])),
        };
        Eval {
            val: Val::Produced(produced),
            code: Code::Rust(quote!({
                #file
                ::hyperscale_vm_sdk::state::mint_nf_granted(#grant, #id_value)
            })),
        }
    }

    /// Lower `Name::burn(funds)`.
    ///
    /// What it destroys is the resource the mark derives, so an edge a
    /// caller supplied is held to that resource exactly as a credit to a
    /// cell holding it would be — and one the body produced is compared
    /// outright, because no caller is involved to be constrained.
    pub(super) fn lower_burn(&mut self, mark: &[u8], call: &syn::ExprCall) -> Eval {
        let Some(destroyed) = call.args.first().map(|a| self.expr(a)) else {
            self.error(call.args.span(), "a burn with nothing to destroy");
            return Eval::absent(call.args.span(), "a burn with no value");
        };
        let held = Term::SelfResource(ResourceKind::Fungible, mark.to_vec());
        match Self::edge_resource(&destroyed) {
            Some(Term::ResourceOf(inner)) if matches!(*inner, Term::Arg(_)) => {
                if let Term::Arg(param) = *inner {
                    self.denominate(param, held, call.span());
                }
            }
            Some(carried) if carried != held => {
                let (carried, held) = (self.describe(&carried), self.describe(&held));
                self.error(
                    call.args.span(),
                    &format!(
                        "this destroys {carried} against a grant over {held}. A grant is \
                         authority over one resource, and burning is that authority in the \
                         other direction"
                    ),
                );
            }
            Some(_) => {}
            None => self.error(
                call.args.span(),
                "the lowering cannot see what this destroys. Burn an edge the method was \
                 handed, one taken from a declared cell, or one it minted",
            ),
        }
        let funds = self.value(destroyed.code);
        self.issuer(ResourceKind::Fungible, mark, Issued::Burned);
        Eval::plain(quote!(::hyperscale_vm_sdk::state::burn_granted(#funds)))
    }

    /// Lower `halt(holder, resource)` and `unhalt(..)` — the holder's
    /// flag for one resource, under the holder's own prefix.
    ///
    /// The site is a reaching one, so the declaration carries the
    /// authority it acts under and admission carries the entry. Nothing
    /// here judges who may: a package writing this has said it is acting
    /// as the resource's halter, and whether it is, is the resource's
    /// answer.
    ///
    /// Two calls rather than a cell a body reads: the flag's whole
    /// content is whether it is there, so raising it and ending it are
    /// the operations and there is nothing to get.
    pub(super) fn lower_halt(&mut self, raising: bool, call: &syn::ExprCall) -> Eval {
        let spelling = if raising { "halt" } else { "unhalt" };
        // `Resource::halt(holder)` names the resource by its mark and the
        // holder alone; the free form names both, for the resource a
        // package does not issue and has no mark for.
        let (named, marked) = self.reached_resource(call, spelling, GrantedBehaviour::Halt);
        let holder = match (named.as_slice(), marked) {
            ([holder], Some(resource)) => Some((*holder, resource)),
            ([holder, resource], None) => self.expr(resource).val.term().map(|r| (*holder, r)),
            _ => None,
        };
        let Some((holder, resource)) = holder else {
            self.error(
                call.args.span(),
                &format!(
                    "`{spelling}` names the holder whose movement is stopped and the \
                     resource it is stopped for — `Resource::{spelling}(holder)` where this \
                     package issues it, or `{spelling}(holder, resource)` where it does not"
                ),
            );
            return Eval::absent(call.args.span(), "a halt naming neither party");
        };
        let holder = self.expr(holder);
        let Val::Term(holder) = holder.val else {
            self.error(
                call.args.span(),
                &format!(
                    "`{spelling}` names a holder the declaration can see — an argument, or a \
                     configuration field"
                ),
            );
            return Eval::absent(
                call.args.span(),
                "a halt over a value the lowering cannot see",
            );
        };
        let site = self.open_reaching(
            Target::Point {
                owner: Some(holder),
                slot: SlotRef::Fixed(HALT.0),
                material: vec![resource],
            },
            None,
            None,
            Some(GrantedBehaviour::Halt),
        );
        self.record(site, Op::Set, None, call.span());
        let handle = self.handle(site, call.span());
        let body = if raising {
            quote!(::hyperscale_vm_sdk::state::raise_halt(#handle))
        } else {
            quote!(::hyperscale_vm_sdk::state::clear_halt(#handle))
        };
        Eval::plain(body)
    }

    /// Which cell shape a recall reaches: the mark's declared kind
    /// wherever a mark named the resource, and the spelling otherwise.
    ///
    /// `None` where the two disagree, which only the free spelling can
    /// manage — the mark form has one word and takes the kind from the
    /// declaration. Refused rather than resolved in the mark's favour,
    /// because an author who wrote `recall` of a non-fungible meant one
    /// of two things and the compiler cannot tell which.
    fn recalled_kind(
        &mut self,
        resource: &Term,
        spelled_instances: bool,
        free_spelling: bool,
        call: &syn::ExprCall,
    ) -> Option<bool> {
        let Term::SelfResource(kind, _) = resource else {
            return Some(spelled_instances);
        };
        let declared = *kind == ResourceKind::NonFungible;
        if !free_spelling || declared == spelled_instances {
            return Some(declared);
        }
        let (spelling, is, wanted) = if declared {
            ("recall", "non-fungible", "recall_instances")
        } else {
            ("recall_instances", "fungible", "recall")
        };
        self.error(
            call.func.span(),
            &format!(
                "this resource is {is}, and `{spelling}` reaches the cell the other kind is \
                 kept in — `{wanted}`, or the mark's own `Resource::recall(holder, slot, ..)`, \
                 which takes the kind from the declaration"
            ),
        );
        None
    }

    /// Lower `Resource::recall(holder, slot, moved)` and the free
    /// `recall(holder, slot, resource, amount)` beside it — value taken
    /// out of a prefix that is not this instance's.
    ///
    /// [`Self::lower_halt`]'s shape with a slot the caller names. A
    /// halt has one cell to reach and the vocabulary fixes where it
    /// sits; value sits wherever its holder keeps it, so the slot rides
    /// the declaration as an argument and the band it may name is
    /// judged where it has a value.
    ///
    /// **Which cell shape a recall reaches is the resource's kind**, and
    /// where a mark says the kind the spelling says nothing: a balance
    /// is a leaf and instances are entries of an interval, and the two
    /// are not interchangeable. So a mark picks the shape, and the free
    /// form — whose resource is a configured address the declaration
    /// cannot ask a kind of — takes it from `recall` or
    /// `recall_instances`. A mark named through the free spelling is
    /// held to its own kind, because the declaration knows the answer
    /// and a mismatch would otherwise derive a cell nothing can be in.
    ///
    /// Nothing here judges who may. The package writing this has said it
    /// is acting as the resource's recaller, and whether it is, is the
    /// resource's answer.
    pub(super) fn lower_recall(&mut self, spelled_instances: bool, call: &syn::ExprCall) -> Eval {
        let spelling = if spelled_instances {
            "recall_instances"
        } else {
            "recall"
        };
        let (named, marked) = self.reached_resource(call, spelling, GrantedBehaviour::Recall);
        let reached = match (named.as_slice(), marked) {
            ([holder, slot, moved], Some(resource)) => Some((*holder, *slot, *moved, resource)),
            ([holder, slot, resource, moved], None) => self
                .expr(resource)
                .val
                .term()
                .map(|r| (*holder, *slot, *moved, r)),
            _ => None,
        };
        let Some((holder, slot, moved, resource)) = reached else {
            self.error(
                call.args.span(),
                &format!(
                    "`{spelling}` names the holder reached, the slot they keep the resource \
                     at, and what is taken — `Resource::recall(holder, slot, ..)` where this \
                     package issues it, or `{spelling}(holder, slot, resource, ..)` where it \
                     does not"
                ),
            );
            return Eval::absent(call.args.span(), "a recall naming too little");
        };
        let Some(instances) =
            self.recalled_kind(&resource, spelled_instances, named.len() == 4, call)
        else {
            return Eval::absent(call.func.span(), "a recall of the wrong kind");
        };
        let taken = if instances {
            "the instances"
        } else {
            "the amount"
        };
        let holder = self.expr(holder);
        let slot = self.expr(slot);
        let moved = self.expr(moved);
        let (Val::Term(holder), Val::Term(slot), Val::Term(quantity)) =
            (holder.val, slot.val, moved.val.clone())
        else {
            self.error(
                call.args.span(),
                &format!(
                    "`{spelling}` names a holder, a slot and {taken} the declaration can \
                     see — an argument, or a configuration field"
                ),
            );
            return Eval::absent(
                call.args.span(),
                "a recall over a value the lowering cannot see",
            );
        };
        let (element, target): (syn::Type, Target) = if instances {
            (
                syn::parse_quote!(::hyperscale_vm_sdk::state::NfVault),
                Target::Range {
                    slot: SlotRef::Reached(slot),
                    owner: Some(holder),
                    material: vec![resource.clone()],
                    lo: Term::LitU128(0),
                    hi: Term::LitU128(u128::MAX),
                    cap: None,
                },
            )
        } else {
            (
                syn::parse_quote!(::hyperscale_vm_sdk::state::Vault),
                Target::Point {
                    owner: Some(holder),
                    slot: SlotRef::Reached(slot),
                    material: vec![resource.clone()],
                },
            )
        };
        let site = self.open_reaching(target, Some(element), None, Some(GrantedBehaviour::Recall));
        let op = if instances { Op::Debit } else { Op::Reserve };
        self.record(site, op, Some(quantity.clone()), call.span());
        let handle = self.handle(site, call.span());
        let code = if instances {
            // The interval carries no cap of its own, so what it buys is
            // the count of the ids this take names — the derivation a
            // body's own take through `all()` makes.
            self.out.sites[site].moved = Some(Term::Len(Box::new(quantity.clone())));
            let ids = self.value(moved.code);
            quote!(::hyperscale_vm_sdk::state::take_instances(#handle, #ids))
        } else {
            // The amount reaches the guest through nothing: the kernel
            // judged and held the reservation against this declaration
            // before the body ran.
            quote!(::hyperscale_vm_sdk::state::take_reservation(#handle))
        };
        // What the produced edge carries. A balance is the resource
        // alone; instances are the resource and the ids this take names,
        // which is what makes the edge routable before anything runs.
        let produced = if instances {
            Term::NfBucket {
                resource: Box::new(resource),
                ids: Box::new(quantity),
            }
        } else {
            resource
        };
        Eval {
            val: Val::Produced(produced),
            code: Code::Rust(code),
        }
    }

    /// Lower `destroy(funds)` — value the caller handed over, retired
    /// under its own resource's rule.
    ///
    /// The parameter is what the declaration can name, so an edge the
    /// body produced or took from a cell is refused: the grant is per
    /// bucket and resolved where the edge binds, and there is no bound
    /// edge for one a body made up.
    pub(super) fn lower_destroy(&mut self, name: &str, call: &syn::ExprCall) -> Eval {
        let Some(destroyed) = call.args.first().map(|a| self.expr(a)) else {
            self.error(call.args.span(), "a destruction with nothing to destroy");
            return Eval::absent(call.args.span(), "a destruction with no value");
        };
        let param = match Self::edge_resource(&destroyed) {
            Some(Term::ResourceOf(inner)) => match *inner {
                Term::Arg(param) => Some(param),
                _ => None,
            },
            _ => None,
        };
        let Some(param) = param else {
            self.error(
                call.args.span(),
                "`destroy` retires value the caller handed over, so it names a bucket \
                 parameter — what a body issues is retired by its own mark's `burn`, under \
                 the grant that made it",
            );
            return Eval::absent(call.args.span(), "a destruction of an unnamed edge");
        };
        self.out.destroys.push(param);
        let funds = self.value(destroyed.code);
        let spelling = syn::Ident::new(name, call.func.span());
        Eval::plain(quote!(::hyperscale_vm_sdk::state::#spelling(#funds)))
    }
}

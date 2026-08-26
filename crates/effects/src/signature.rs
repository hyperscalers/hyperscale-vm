//! The effect-signature vocabulary: what a published method declares
//! about its parameters and its ABI binding.

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::{CallTarget, ComponentAddr, PackageAddr, PrincipalAddr, ResourceAddr};

use crate::dsl::{Clause, Expr};
use crate::resource::{GrantedBehaviour, GrantsExpr, ResourceKind};
use crate::rule::{RuleExpr, RuleLeaf, StoredRule};
use crate::types::{MAX_IDS_PER_EDGE, Value};

/// A method parameter's admitted kind. Bucket parameters consume a value
/// edge; every other kind binds a literal or envelope input.
///
/// An address parameter declares the classes it admits — the wide kind
/// for any, a position or class kind for fewer — and admission refuses a
/// literal outside them. That refusal is what lets a body read the
/// parameter at the narrow type with no failure arm of its own.
///
/// The variants are grouped — numbers, bytes, addresses widest first,
/// authority, then the two edge kinds — and the grouping is the wire
/// format, not a tidying: nothing here carries a discriminant of its
/// own, so a signature's parameter list is encoded by declaration order.
/// A new kind goes where it belongs among its neighbours, which moves
/// the ones below it; appending to dodge that is how a list stops
/// meaning anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum ParamType {
    /// An unsigned 64-bit integer.
    U64,
    /// An unsigned 128-bit integer.
    U128,
    /// An unsigned 256-bit integer, little-endian — the width a stored
    /// rate has.
    ///
    /// The kind a rate crosses at. A configuration slot has held one
    /// since a rate could be configured; a parameter holds one so that
    /// the number an oracle posts says what it means where it is written,
    /// rather than being a scaled integer and a comment agreeing.
    U256,
    /// Opaque bytes.
    Bytes,
    /// A global object's address, of any class.
    Address,
    /// An address a method may be invoked on: a principal or a component.
    CallTarget,
    /// A principal's address.
    Principal,
    /// A component instance's address.
    Component,
    /// A package's address.
    Package,
    /// A resource's address: what an amount is denominated in.
    Resource,
    /// An authority rule, carried as its canonical bytes and decoded as
    /// the vocabulary at admission — so a rule past a cap, or with a
    /// degenerate threshold, is refused before anything signs.
    Rule,
    /// A set of non-fungible instance ids: a list of distinct `u64`s
    /// within the per-edge cap. Signed manifest content — a transfer
    /// names the ids it moves; nothing about an instance is resolved at
    /// execution.
    Ids,
    /// A fungible value edge; its resource type is static, its amount
    /// dynamic.
    ///
    /// Which of the two edge kinds a method consumes is part of its
    /// signature rather than a fact about whichever edge is routed in:
    /// the two cross the boundary as different cells, so a callee that
    /// did not say would be one whose guest had to sniff what it was
    /// handed.
    Bucket,
    /// A non-fungible value edge, carrying the instances it moves rather
    /// than an amount.
    NfBucket,
}

impl ParamType {
    /// Whether this kind is a value edge, of either edge kind.
    ///
    /// What the two share is how they are supplied — an edge, never a
    /// literal — and how they are bound, through [`AbiParam::Bucket`].
    /// What separates them is the cell they cross as.
    #[must_use]
    pub const fn is_edge(self) -> bool {
        matches!(self, Self::Bucket | Self::NfBucket)
    }

    /// The edge kind this parameter accepts, if it is an edge at all.
    #[must_use]
    pub const fn edge_kind(self) -> Option<ResourceKind> {
        match self {
            Self::Bucket => Some(ResourceKind::Fungible),
            Self::NfBucket => Some(ResourceKind::NonFungible),
            _ => None,
        }
    }

    /// The kind name, for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::U256 => "u256",
            Self::Bytes => "bytes",
            Self::Address => "address",
            Self::CallTarget => "call-target",
            Self::Principal => "principal-address",
            Self::Component => "component-address",
            Self::Package => "package-address",
            Self::Resource => "resource-address",
            Self::Rule => "rule",
            Self::Ids => "ids",
            Self::Bucket => "bucket",
            Self::NfBucket => "nf-bucket",
        }
    }

    /// Whether this kind binds an address literal, of any narrowing.
    #[must_use]
    pub const fn is_address(self) -> bool {
        matches!(
            self,
            Self::Address
                | Self::CallTarget
                | Self::Principal
                | Self::Component
                | Self::Package
                | Self::Resource
        )
    }

    /// Whether a literal value has this kind. Buckets are never literals —
    /// they arrive only as edges, and a rule is bytes that decode as the
    /// vocabulary. A narrowed address kind admits only its own classes,
    /// judged by the conversion the narrow type itself defines.
    #[must_use]
    pub fn admits(self, value: &Value) -> bool {
        match (self, value) {
            (Self::U64, Value::U64(_))
            | (Self::U128, Value::U128(_))
            | (Self::U256, Value::U256(_))
            | (Self::Bytes, Value::Bytes(_))
            | (Self::Address, Value::Address(_)) => true,
            (Self::CallTarget, Value::Address(address)) => CallTarget::try_from(*address).is_ok(),
            (Self::Principal, Value::Address(address)) => PrincipalAddr::try_from(*address).is_ok(),
            (Self::Component, Value::Address(address)) => ComponentAddr::try_from(*address).is_ok(),
            (Self::Package, Value::Address(address)) => PackageAddr::try_from(*address).is_ok(),
            (Self::Resource, Value::Address(address)) => ResourceAddr::try_from(*address).is_ok(),
            (Self::Rule, Value::Bytes(bytes)) => StoredRule::from_slice(bytes).is_ok(),
            (Self::Ids, Value::List(elements)) => {
                elements.len() <= MAX_IDS_PER_EDGE
                    && elements.iter().enumerate().all(|(position, element)| {
                        matches!(element, Value::U64(_)) && !elements[..position].contains(element)
                    })
            }
            _ => false,
        }
    }
}

/// How one guest ABI parameter is built at invocation.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum AbiParam {
    /// The site this method's handle parameter covers.
    ///
    /// Names a clause and a site within it rather than a position in the
    /// materialized table: a `for-each` clause expands over instance
    /// configuration, so table positions past one would depend on
    /// configuration rather than on the signature. A plain clause is one
    /// site of its own, named at site zero.
    ///
    /// The width is the instance's rather than the signature's, which is
    /// why one parameter covers a whole site and not one element of it — a
    /// body's arity stays a function of what it declares, and the list a
    /// loop maps over stays the configuration's business. An element the
    /// site's guard did not fire for reads absent at its index rather
    /// than shortening the walk, so two sites in one body agree on what
    /// an index means.
    Handle {
        /// The top-level clause.
        clause: u32,
        /// The site's position in that clause's body, or zero where the
        /// clause is one access of its own.
        site: u32,
    },
    /// The value edge this declared [`ParamType::Bucket`] parameter is
    /// bound to.
    ///
    /// The one argument a signature cannot derive: which bucket it is
    /// depends on what the producing node handed back, which does not
    /// exist until that node runs.
    Bucket(u32),
    /// Whether the clause this names was declared: the guard's own
    /// verdict, as a `bool` the export takes.
    ///
    /// Answered from [`Declaration::clause_taken`], which the evaluation
    /// routing already ran has recorded — so the guest branches on the
    /// declaration rather than on a second copy of the condition, and
    /// there is nothing for the two to disagree about. A body whose
    /// control flow diverges from the flag it was handed reaches a
    /// capability that was never materialized, which is a defect and
    /// traps as one.
    ///
    /// [`Declaration::clause_taken`]: crate::dsl::Declaration::clause_taken
    Guard(u32),
    /// A value evaluated over the method's bound inputs.
    ///
    /// The same evaluation the effect clauses run, against the same
    /// inputs — arguments, instance configuration, and the identity,
    /// node and frame a fresh id derives from — so an argument the guest
    /// reads is bounded and deterministic on exactly the terms a declared
    /// target already is. Everything but a value edge lands here.
    Derived(Expr),
}

/// How completely a method can be relied on to return.
///
/// Three states rather than a flag, because the two facts behind them are
/// not the same fact and one does not imply the other. An error arm is
/// visible in the signature and says the method can fail on its own terms.
/// Trap freedom is not visible anywhere — a trap leaves the type system
/// entirely — so ruling it out takes analysis of the body rather than a
/// reading of its declaration.
///
/// The variants sit weakest first. The default is not the weakest but
/// the commonest: the mark is a function of the component type rather
/// than a claim an author may under-shoot, and a method with no error
/// arm is the shape most methods have.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hbor)]
pub enum Totality {
    /// The signature carries an error arm, so the method fails on its own
    /// terms and every caller has a failure to handle. The publish gate
    /// admits this mark exactly over an export that carries one.
    Fallible,
    /// No error arm, and nothing established about traps. Necessary for
    /// [`Total`](Self::Total) and not sufficient for it: fuel exhaustion
    /// and a panicking body are both still reachable from here.
    #[default]
    Infallible,
    /// No error arm, and the publish-time checker established the rest:
    /// no partial operation anywhere in the body, and a static
    /// fuel bound the transaction pre-charges so exhaustion cannot occur
    /// at execution. Never authored — a package claims it and the check
    /// grants it, because a claim a package could simply assert about
    /// itself would carry no weight for the shards that rely on it.
    Total,
}

impl Totality {
    /// Whether a caller may commit without waiting to hear back.
    #[must_use]
    pub const fn is_total(self) -> bool {
        matches!(self, Self::Total)
    }
}

/// The bound on how many resources one method may issue.
///
/// A component founds every resource it declares in the one call that
/// makes it actual, so the ceiling is the marks a package may declare
/// rather than anything a method chooses — and the cost of each is a
/// derivation at admission, which is what this bounds.
pub const MAX_ISSUANCES_PER_SIGNATURE: usize = 16;

/// The bound on how many claims one method's gate may mint.
///
/// A gate mints the one claim its target names, or two where an instance
/// widens to its resource, so this is headroom rather than a limit an
/// author meets. It is a cap and not a comment because the minted set is
/// what every later node presenting this one's proof copies: a signature
/// free to mint thousands would let one evidence edge carry thousands,
/// and a graph of them would cost the ingress that admits it far more
/// than the sender pays to be refused.
pub const MAX_MINTS_PER_SIGNATURE: usize = 8;

/// Which directions a declared issuance takes.
///
/// Two entries cannot be independent over one undirected grant: a
/// burn-only frame asked the mint rule would be held to an authority it
/// never uses, and a mint-only frame asked the burn rule likewise. So
/// the declaration says which, read off the body that issues — the same
/// way a credit-only access is told from one that also debits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Issued {
    /// Brings supply into existence and never takes it out.
    Minted,
    /// Takes supply out and never brings it in.
    Burned,
    /// Both, through one grant over one resource.
    Either,
}

impl Issued {
    /// The behaviours a frame declaring this direction is held to.
    #[must_use]
    pub const fn behaviours(self) -> &'static [GrantedBehaviour] {
        match self {
            Self::Minted => &[GrantedBehaviour::Mint],
            Self::Burned => &[GrantedBehaviour::Burn],
            Self::Either => &[GrantedBehaviour::Mint, GrantedBehaviour::Burn],
        }
    }

    /// Whether this direction brings supply into existence.
    #[must_use]
    pub const fn mints(self) -> bool {
        matches!(self, Self::Minted | Self::Either)
    }

    /// Whether this direction takes supply out of existence.
    #[must_use]
    pub const fn burns(self) -> bool {
        matches!(self, Self::Burned | Self::Either)
    }

    /// The direction a body reaching both ways takes, folded one call at
    /// a time.
    #[must_use]
    pub const fn with(self, also: Self) -> Self {
        match (self, also) {
            (Self::Minted, Self::Minted) => Self::Minted,
            (Self::Burned, Self::Burned) => Self::Burned,
            _ => Self::Either,
        }
    }
}

/// The resource a method's issuance grant is over: the mark deriving it,
/// the kind it is, and which way it goes.
///
/// The kind travels with the mark because the derivation folds it — the
/// grant's address is a function of both — and because a burn-only
/// method has no output projection to read a kind from, so nothing else
/// in the signature could say it. The direction travels for the same
/// reason: it is the body's fact, and a burn has nothing else to read it
/// off.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct Issuance {
    /// The material separating this resource from the instance's others.
    pub mark: Vec<u8>,
    /// What the resource is, folded into its derivation.
    pub kind: ResourceKind,
    /// Which way this frame's issuance goes, and therefore which of the
    /// resource's authority entries it is held to.
    pub direction: Issued,
    /// The rules the resource's address grants, resolved against the
    /// instance issuing them where the grant is derived.
    ///
    /// The same set the declaration's own `SelfResource` expressions
    /// carry, because it has to be the same address: a gate naming the
    /// resource and the grant that mints it derive through one
    /// commitment, so the tier has a minter rather than only a verifier.
    pub grants: GrantsExpr,
}

/// A method's declared access: every effect the method itself reaches,
/// and no further — a frame declares only under its own instance's
/// prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
pub struct MethodSignature {
    /// How completely the method returns: whether a caller has a failure
    /// to handle, and whether anything rules out a trap.
    ///
    /// What a leg's decomposition turns on — an outbound leg commits
    /// locally and offers no veto, so it must be one that cannot come
    /// back with a refusal or a trap for the core to have to answer.
    pub totality: Totality,
    /// The resources this method may bring into or out of existence,
    /// in the order a body's own calls name them.
    ///
    /// Marks rather than addresses: a mark is the material separating one
    /// of the instance's own resources from its others, so naming another
    /// instance's is not something this field can say. The walk grants
    /// each against the target, and the position here is the index the
    /// export passes — so a component founding three resources says
    /// which of them each call means.
    #[hbor(max = MAX_ISSUANCES_PER_SIGNATURE)]
    pub issues: Vec<Issuance>,
    /// The value edges this method destroys, by parameter position.
    ///
    /// The other way supply leaves existence, and the one an issuer does
    /// not perform: what is destroyed is the *edge's* resource rather
    /// than one this instance derives, so the grant is per bucket and
    /// the entry that admits it is the resource's own `Burn`, resolved
    /// at admission from the record the caller presented. Absence of
    /// either withholds the capability, which is what makes "anyone may
    /// destroy what they hold" a rule the issuer writes rather than a
    /// power the kernel hands out.
    #[hbor(max = MAX_ISSUANCES_PER_SIGNATURE)]
    pub destroys: Vec<u32>,
    /// The method's parameter kinds, in order; admission types every node
    /// against them.
    pub params: Vec<ParamType>,
    /// The static resource type of each value edge the method produces, as
    /// an expression over the method's bound inputs.
    pub outputs: Vec<Expr>,
    /// Whether the method hands back a value beside its edges.
    ///
    /// A caller reads it off the receipt rather than routing it, so what
    /// a manifest needs from this is only that such a result is not an
    /// output slot. The gate holds it against what the export's own type
    /// hands back, as it does the edges and the error arm.
    pub answers: bool,
    /// The resource each value edge the method *consumes* must carry, as
    /// an expression over the method's bound inputs; `None` at a position
    /// that takes any resource.
    ///
    /// The dual of `outputs`, and one entry per parameter, so a position
    /// indexes both this and `params`. What fixes an entry is the body: a
    /// bucket credited to a cell the method keys by something other than
    /// that bucket's own resource is a bucket the method can only mean one
    /// resource by. A cell keyed by the arriving resource fixes nothing,
    /// which is what a wallet is, and leaves the position open.
    ///
    /// Not derivable from the effects alone: a clause names the cell and
    /// never which parameter feeds it.
    pub denominations: Vec<Option<Expr>>,
    /// The method's own effect clauses.
    pub effects: Vec<Clause>,
    /// How the guest's ABI parameters are built, one entry per exported
    /// parameter in the export's own order.
    ///
    /// A socket list has no arity relation to the ABI: the
    /// capability table mediates, so a method declaring one bucket and two
    /// effects can export two arguments of which one is a handle for the
    /// first effect's target and the other the bucket's bytes. Nothing
    /// else in the signature says which, and without saying it a caller
    /// has to know the method — which is why a dispatch table that knows
    /// every method by name is the only thing that can call one.
    ///
    /// Authored beside the signature and content-addressed with the code,
    /// so the binding cannot drift from the ABI it describes.
    pub abi: Vec<AbiParam>,
}

impl MethodSignature {
    /// Whether a call to this method must present evidence: its
    /// accessibility gate, or any authority condition its declaration
    /// requires.
    #[must_use]
    pub fn requires_evidence(&self) -> bool {
        self.required_rules().next().is_some()
    }

    /// Whether admission may inject an authority requirement onto this
    /// method's frame.
    ///
    /// The three things that earn one: bringing supply into existence,
    /// taking it out, and reaching a prefix that is not this instance's
    /// own. None of them is *declared* as a condition — the entry comes
    /// from the resource, which is what makes omission inexpressible —
    /// so a caller reading only [`requires_evidence`](Self::requires_evidence)
    /// would conclude the method admits anyone and refuse to hand it a
    /// proof it turns out to need.
    ///
    /// Answered from the signature alone and deliberately loose: whether
    /// the entry actually demands anything depends on the resource and
    /// on the instance, and the composer's job here is only to stop
    /// ruling a proof out.
    #[must_use]
    pub fn may_earn_authority(&self) -> bool {
        !self.issues.is_empty()
            || !self.destroys.is_empty()
            || self
                .effects
                .iter()
                .flat_map(Clause::effects)
                .any(|clause| matches!(clause, Clause::Effect { reach: Some(_), .. }))
    }

    /// Whether judging this method reads a stored rule — which is what
    /// admits a signature as evidence: a signature signs in, and whether
    /// the key behind it still holds its account's authority is the
    /// stored rule's own question.
    #[must_use]
    pub fn reads_a_rule(&self) -> bool {
        self.required_rules()
            .flat_map(RuleExpr::leaves)
            .any(|leaf| matches!(leaf, RuleLeaf::Stored { .. }))
    }

    /// Whether a call to this method mints a claim: any `Mints` clause
    /// its declaration states.
    #[must_use]
    pub fn mints(&self) -> bool {
        self.effects
            .iter()
            .flat_map(Clause::effects)
            .any(|clause| matches!(clause, Clause::Mints { .. }))
    }

    /// Every rule a `Requires` clause of this declaration states that a
    /// caller could have to satisfy, in preorder.
    ///
    /// A rule answerable from committed state alone is not one: it states
    /// a feasibility fact, judged before any body runs, and turns no
    /// caller away — so it is no part of what a call must present.
    fn required_rules(&self) -> impl Iterator<Item = &RuleExpr> {
        self.effects
            .iter()
            .flat_map(Clause::effects)
            .filter_map(|clause| match clause {
                Clause::Requires { rule, .. } if !rule.reads_state_only() => Some(rule),
                _ => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two integer widths do not stand in for one another.
    ///
    /// What a rate parameter is for is that the scale rides the value, so
    /// a caller handing over the bare number it was scaled from is the
    /// mistake the kind exists to refuse — and a `u128` position handed a
    /// rate is the same mistake read the other way.
    #[test]
    fn a_rate_parameter_and_an_amount_do_not_admit_each_others_literals() {
        let rate = Value::U256([7; 32]);
        let amount = Value::U128(7);
        assert!(ParamType::U256.admits(&rate));
        assert!(ParamType::U128.admits(&amount));
        assert!(!ParamType::U256.admits(&amount), "a rate is not its scale");
        assert!(!ParamType::U128.admits(&rate), "and an amount is not one");
    }

    #[test]
    fn an_ids_parameter_admits_only_a_bounded_duplicate_free_id_list() {
        let ids = |raw: &[u64]| Value::List(raw.iter().copied().map(Value::U64).collect());
        assert!(ParamType::Ids.admits(&ids(&[])));
        assert!(ParamType::Ids.admits(&ids(&[7, 9])));
        assert!(!ParamType::Ids.admits(&ids(&[7, 7])), "a duplicate id");
        let over_cap: Vec<u64> = (0..=MAX_IDS_PER_EDGE as u64).collect();
        assert!(!ParamType::Ids.admits(&ids(&over_cap)), "past the cap");
        assert!(
            !ParamType::Ids.admits(&Value::List(vec![Value::U128(7)])),
            "an element that is not an id"
        );
        assert!(!ParamType::Ids.admits(&Value::U64(7)), "not a list at all");
    }

    #[test]
    fn an_address_parameter_admits_exactly_its_declared_classes() {
        use hyperscale_vm_types::{Address, AddressClass};

        let of = |class: AddressClass| Value::Address(Address::new([7; 31], class));
        // Every class, so a parameter's answer is stated for each rather
        // than left to whichever ones a case happened to list. The one
        // that matters is `Restricted`: it is a resource, so a parameter
        // that admits resources admits it, and a sweep omitting it never
        // exercises the widening it exists to protect.
        let classes = [
            AddressClass::Principal,
            AddressClass::Component,
            AddressClass::Package,
            AddressClass::Resource,
            AddressClass::Restricted,
            AddressClass::Native,
        ];
        let admitted: &[(ParamType, &[AddressClass])] = &[
            (ParamType::Address, &classes),
            (
                ParamType::CallTarget,
                &[AddressClass::Principal, AddressClass::Component],
            ),
            (ParamType::Principal, &[AddressClass::Principal]),
            (ParamType::Component, &[AddressClass::Component]),
            (ParamType::Package, &[AddressClass::Package]),
            (
                ParamType::Resource,
                &[AddressClass::Resource, AddressClass::Restricted],
            ),
        ];
        for (param, admits) in admitted {
            assert!(param.is_address());
            for class in classes {
                assert_eq!(
                    param.admits(&of(class)),
                    admits.contains(&class),
                    "{} against {class}",
                    param.name()
                );
            }
            assert!(
                !param.admits(&Value::U64(7)),
                "{} a non-address",
                param.name()
            );
        }
    }
}

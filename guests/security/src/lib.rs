//! A share class whose holders are a register, and the register itself.
//!
//! The authoring side of the movement seam: everything the custodian
//! establishes is about a package that declares *nothing*, and this is
//! the package that declares the rule being enforced. Between them the
//! mechanism is closed at both ends — one resource says who may move it,
//! and no holder of it, however written, can decline to be asked.
//!
//! Two resources and the difference between them is the whole design.
//! `Share` puts both directions of a movement on the register, so it
//! leaves a holder exactly while the register says so and reaches only
//! somebody the register admits — standing facts about the two parties,
//! each read under their own prefix, with no proof presented and nothing
//! about the caller consulted. `Registered` grants `withdraw = nobody`,
//! so the entry itself can never leave the holder it was issued to: a
//! credential somebody can hand on is a register somebody else can join
//! without the registrar.
//!
//! That pairing is why a badge carries its own rules into the leaf that
//! names it. `Registered`'s address is the hash of `withdraw = nobody`,
//! so a `Share` rule deriving the badge through the granting-nothing form
//! would name an address nothing is ever minted at — and since a
//! credential is soulbound whenever it is any good, that is the ordinary
//! case rather than a corner of one.
//!
//! `Approved` is the same design in the other posture. Its entries name
//! the registrar's own identity rather than the register entry, so a
//! movement of it asks about the transaction instead of about the
//! holder: not "is this party on the register" but "did the registrar
//! sign this". One authoring word covers both, because the subject
//! decides which question is answerable — a resource can be held and an
//! identity can only be presented.
//!
//! `Bearer` is here to be the control. Same issuer, same shape, an
//! authority entry and no movement one — so its address stays plain
//! `Resource` while `Share`'s is `Restricted`, and the class byte is
//! shown to follow what the entries *do* rather than whether a resource
//! grants anything at all.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod security {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Ids, NfBucket, Quantity};

    /// The register entry: one instance per registration.
    ///
    /// Non-fungible, and the price is the whole of the choice. Asking
    /// whether a party is on the register reads one leaf either way —
    /// a balance cell, or the holder's own interval for this badge —
    /// but an interval is *priced* by the span it declares, so every
    /// movement of the share class pays for a question spanning the id
    /// space where a balance would have paid for a cell. That cost is on
    /// the transfer path, and it is on it forever.
    ///
    /// What it buys is entries a registrar can tell apart. A balance
    /// says how much and never which, so revoking is by amount and one
    /// registration is indistinguishable from another; instances make a
    /// registration a thing with a name, revoked or reissued one holder
    /// at a time. A fungible register remains the right choice for an
    /// issuer who will never need to name one, and it is spellable in
    /// exactly these words with the kind changed.
    ///
    /// Soulbound: `withdraw = nobody` refuses every debit of it at
    /// admission, so it leaves a holder only when the registrar takes it
    /// back — which is what the `recall` entry beside it is for. The two
    /// together are the whole of a revocable credential: nobody hands it
    /// on, and one party can take it away.
    #[resource(non_fungible, grants(mint = self, withdraw = nobody, recall = registrar))]
    struct Registered;

    /// The share class. Moved by a registered holder to a registered
    /// holder and by nobody else, wherever it is held and through
    /// whatever package holds it.
    ///
    /// Two entries over one register, and they are two authorizations
    /// rather than a relation between the parties: neither names the
    /// other side of the edge, so what each says is that the party whose
    /// vault moves is on the register. "Alice may send to Bob but not to
    /// Carol" is not spellable here and belongs to whoever keeps the
    /// register.
    #[resource(grants(
        mint = self,
        withdraw = issued(Registered),
        deposit = issued(Registered),
        freeze = registrar,
        recall = registrar
    ))]
    struct Share;

    /// The same share class in the other posture: every movement
    /// approved one at a time, rather than checked against a standing
    /// register.
    ///
    /// The same two entries as `Share` with the subject swapped, and
    /// that is the whole of the difference. A resource can be held, so
    /// naming one asks a standing fact about the party whose vault
    /// moves; an identity cannot be held, so naming one asks the only
    /// other question there is — did this transaction carry a claim on
    /// it. No second authoring word says which, and an integrator reads
    /// the posture off the subject's own address class.
    ///
    /// What it buys is a venue that never onboards. A pool trading
    /// `Share` has to be on the register before it can hold any, so the
    /// issuer admits every venue as well as every holder; a pool
    /// trading this holds none of the issuer's credentials and is bound
    /// anyway, because the registrar signs the transaction the trade
    /// happens in. What it costs is that the registrar is a party to
    /// every movement, where a register is read once and moves nothing.
    #[resource(grants(
        mint = self,
        withdraw = registrar,
        deposit = registrar,
        recall = registrar
    ))]
    struct Approved;

    /// The same issuer's unrestricted class: recallable, and free to
    /// move.
    ///
    /// An authority entry answers for itself — absence of the record
    /// withholds the capability rather than permitting a movement — so
    /// granting one leaves the address plain, and a holder of this pays
    /// nothing on the transfer path.
    #[resource(grants(mint = self, recall = registrar))]
    struct Bearer;

    /// Who keeps the register.
    ///
    /// An identity rather than a badge, and the choice is the
    /// consequential one: a rule naming a badge is mutable by reissuing
    /// it, and a rule naming an identity is frozen for the life of the
    /// resource. An issuer wanting the registrar to be replaceable names
    /// their own component here.
    #[config]
    struct Terms {
        registrar: Address,
    }

    #[state]
    struct Security {}

    impl Security {
        /// Admit a holder to the register, as the registration `id`.
        ///
        /// The entry leaves as an edge the caller routes to whoever is
        /// being registered — so being on the register is holding one,
        /// and there is no second list that could disagree with the leaf
        /// the movement seam actually reads.
        ///
        /// The id is the registrar's to choose and is what makes a
        /// registration nameable afterwards. Nothing on the transfer
        /// path reads it: what a movement asks is whether the holder's
        /// interval holds anything at all.
        #[requires(registrar)]
        pub fn register(&mut self, id: u64) -> NfBucket {
            Registered::mint(id)
        }

        /// Issue shares.
        pub fn issue(&mut self, amount: Quantity) -> Bucket {
            Share::mint(amount)
        }

        /// Stop `holder` moving the share class, wherever they hold it.
        ///
        /// The one cell this package writes under somebody else's
        /// prefix, and it declares no gate of its own: what admits the
        /// reach is the share's own `freeze` entry, injected where the
        /// declaration is evaluated. Named on the mark, so the resource
        /// this halts is the resource the declaration derives and there
        /// is no second spelling to disagree with it. A holder does not have to cooperate
        /// and cannot be written to cooperate — which is the whole
        /// difference from a fence a holder's package would have had to
        /// declare.
        pub fn freeze(&mut self, holder: Address) {
            Share::halt(holder);
        }

        /// Let them move again. The flag's absence is the unfrozen
        /// state, so lifting it is ending the cell.
        pub fn release(&mut self, holder: Address) {
            Share::unhalt(holder);
        }

        /// Issue the approval-gated class.
        pub fn issue_approved(&mut self, amount: Quantity) -> Bucket {
            Approved::mint(amount)
        }

        /// Issue the unrestricted class.
        pub fn issue_bearer(&mut self, amount: Quantity) -> Bucket {
            Bearer::mint(amount)
        }

        /// Take `amount` of the share class out of the vault `holder`
        /// keeps it in at `slot`.
        ///
        /// The slot is the caller's because a holder keeps value
        /// wherever they like: an account keeps it at the vocabulary's
        /// vault, an application at one of its own. A recall that could
        /// only name the first would stop at the first deposit into any
        /// component, which is the hole the reach exists to close.
        ///
        /// Every rule the share class carries would refuse this if it
        /// were asked, and none of them is: the recall's own entry is
        /// what admits it, and a movement requirement fires against the
        /// party being reached, who by construction fails it. That is
        /// the whole of why a frozen holder is recallable and a holder
        /// off the register is too.
        pub fn recall_shares(&mut self, holder: Address, slot: u64, amount: Quantity) -> Bucket {
            Share::recall(holder, slot, amount)
        }

        /// Take the named registrations back, which is the only way
        /// one ever moves.
        ///
        /// `withdraw = nobody` means the holder cannot hand one on and
        /// no package holding it can be made to release it, so
        /// revocation is not a courtesy the holder extends — it is the
        /// registrar's own entry, read where the declaration is
        /// evaluated.
        ///
        /// The registrations are named rather than counted, which is
        /// what the non-fungible kind was bought for: a registrar
        /// revoking one of a holder's two says which. Nothing here says
        /// so twice — the same `recall` the share class uses, taking its
        /// cell shape and its edge type from the mark's own declared
        /// kind.
        pub fn revoke(&mut self, holder: Address, slot: u64, ids: Ids) -> NfBucket {
            Registered::recall(holder, slot, ids)
        }
    }
}

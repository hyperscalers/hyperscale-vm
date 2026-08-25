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
//! each read as one leaf under their own prefix, with no proof presented
//! and nothing about the caller consulted. `Registered` grants
//! `withdraw = nobody`, so the entry itself can never leave the holder it
//! was issued to: a credential somebody can hand on is a register
//! somebody else can join without the registrar.
//!
//! That pairing is why a badge carries its own rules into the leaf that
//! names it. `Registered`'s address is the hash of `withdraw = nobody`,
//! so a `Share` rule deriving the badge through the granting-nothing form
//! would name an address nothing is ever minted at — and since a
//! credential is soulbound whenever it is any good, that is the ordinary
//! case rather than a corner of one.
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
    use hyperscale_vm_sdk::state::{Bucket, Quantity, halt, recall, unhalt};

    /// The register entry: one fungible unit per registered holder.
    ///
    /// Fungible because a credential is a presence question and a
    /// balance is one leaf. A non-fungible register is spellable in the
    /// same words — the holdings interval answers whether it holds
    /// anything — and costs the whole id space in exclusion where this
    /// costs one cell, so the kind is the issuer's price for telling
    /// entries apart. Where terms have to travel with a holder, they
    /// belong on a data instance beside this, which nothing on the
    /// transfer path decodes.
    ///
    /// Soulbound: `withdraw = nobody` refuses every debit of it at
    /// admission, so it leaves a holder only when the registrar takes it
    /// back — which is what the `recall` entry beside it is for. The two
    /// together are the whole of a revocable credential: nobody hands it
    /// on, and one party can take it away.
    #[resource(grants(mint = self, withdraw = nobody, recall = registrar), display_digits = 0)]
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
        /// Admit a holder to the register.
        ///
        /// The unit leaves as an edge the caller routes to whoever is
        /// being registered — so being on the register is holding the
        /// entry, and there is no second list that could disagree with
        /// the leaf the movement seam actually reads.
        #[requires(registrar)]
        pub fn register(&mut self) -> Bucket {
            Registered::mint(Quantity::from_subunits(1))
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
        /// declaration is evaluated. A holder does not have to cooperate
        /// and cannot be written to cooperate — which is the whole
        /// difference from a fence a holder's package would have had to
        /// declare.
        pub fn freeze(&mut self, holder: Address) {
            halt(holder, Share::address());
        }

        /// Let them move again. The flag's absence is the unfrozen
        /// state, so lifting it is ending the cell.
        pub fn release(&mut self, holder: Address) {
            unhalt(holder, Share::address());
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
            recall(holder, slot, Share::address(), amount)
        }

        /// Take `held` of the register entry back, which is the only
        /// way it ever moves.
        ///
        /// `withdraw = nobody` means the holder cannot hand it on and no
        /// package holding it can be made to release it, so revocation
        /// is not a courtesy the holder extends — it is the registrar's
        /// own entry, read where the declaration is evaluated.
        ///
        /// The amount is named because a fungible entry is a balance.
        pub fn revoke(&mut self, holder: Address, slot: u64, held: Quantity) -> Bucket {
            recall(holder, slot, Registered::address(), held)
        }
    }
}

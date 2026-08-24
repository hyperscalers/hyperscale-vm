//! A share class whose holders are a register, and the register itself.
//!
//! The authoring side of the movement seam: everything the custodian
//! establishes is about a package that declares *nothing*, and this is
//! the package that declares the rule being enforced. Between them the
//! mechanism is closed at both ends — one resource says who may move it,
//! and no holder of it, however written, can decline to be asked.
//!
//! Two entries and the difference between them is the whole design.
//! `Share` grants `withdraw = issued(Registered)`, so a holder
//! moves it exactly while the register says so — a standing fact about
//! the mover, read as one leaf under their own prefix, with no proof
//! presented and nothing about the caller consulted. `Registered` grants
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
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    /// The register entry: one fungible unit per registered holder.
    ///
    /// Fungible because a credential is a presence question, and only a
    /// fungible holding is a single leaf — a non-fungible one is entries
    /// at instance ids, and "holds any of them" is an interval no
    /// movement may be priced against. Where terms have to travel with a
    /// holder, they belong on a data instance beside this, which nothing
    /// on the transfer path decodes.
    ///
    /// Soulbound: `withdraw = nobody` refuses every debit of it at
    /// admission, so it leaves a holder only when the registrar takes it
    /// back.
    #[resource(grants(withdraw = nobody), display_digits = 0)]
    struct Registered;

    /// The share class. Movable by a registered holder and nobody else,
    /// wherever it is held and through whatever package holds it.
    #[resource(grants(withdraw = issued(Registered)))]
    struct Share;

    /// The same issuer's unrestricted class: recallable, and free to
    /// move.
    ///
    /// An authority entry answers for itself — absence of the record
    /// withholds the capability rather than permitting a movement — so
    /// granting one leaves the address plain, and a holder of this pays
    /// nothing on the transfer path.
    #[resource(grants(recall = registrar))]
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

        /// Issue the unrestricted class.
        pub fn issue_bearer(&mut self, amount: Quantity) -> Bucket {
            Bearer::mint(amount)
        }
    }
}

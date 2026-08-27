//! The shapes a contract body may take, as a package that has to execute
//! them.
//!
//! What a body *declares* is settled on a host build, where nothing runs.
//! That says nothing about whether the emission has a rewriting for it,
//! because that only shows up when the guest half is compiled — and a
//! shape the declaration admits but the emission cannot write is a
//! package that traces cleanly and will not build.
//!
//! So this crate is the emission's side of the same question: every shape
//! below is here because it is one the grammar admits, and the check is
//! that `cargo hyperscale` gets an artifact out of it — and, for the
//! shapes whose halves a host build cannot tell apart, that running it
//! answers what running the bodies did.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod grammar {
    use hyperscale_vm_sdk::state::{
        Bucket, Cell, Ids, Instances, Keyed, NfBucket, OrderKey, Ordered, Quantity, Table, Vault,
        pack,
    };
    use hyperscale_vm_sdk::{Address, ResourceAddr};

    /// The schedule an instance was created under.
    ///
    /// A table is here because a lookup into one is the term whose whole
    /// point is that the evaluator reaches it and the guest does not:
    /// the rows are the creator's, fixed in the address, and no export
    /// carries them.
    #[config]
    struct Terms {
        /// What each named tier is charged.
        tiers: Table<u64, u64>,
        /// What a tier the schedule does not name is charged.
        fallback: u64,
        /// The parties a schedule is written for, which is the list a
        /// `for-each` maps over.
        sides: Vec<Address>,
        /// The windows a walk over this instance's logs maps over,
        /// each naming a sub-collection of its own.
        windows: Vec<u64>,
        /// The marks whose instances this instance custodies.
        ///
        /// Another instance's, necessarily: a mark derives from the
        /// address of whoever issues it, and this record is sealed
        /// before this instance has one.
        marks: Vec<ResourceAddr>,
        /// The resources a survey of this instance's vaults walks.
        ///
        /// A second list, because a vault is keyed by what it holds: a
        /// loop over it declares a read on a *denominated* leaf, which
        /// is the mode `sides` cannot reach.
        assets: Vec<ResourceAddr>,
    }

    /// A mark carrying a schema: what one of its instances holds, in the
    /// encoding the mark itself declares.
    #[resource(non_fungible, grants(mint = self, burn = self))]
    struct Seat {
        holder: u64,
    }

    #[state]
    struct Grammar {
        entries: Ordered<Quantity>,
        /// A line per window, beside the log the window is read from.
        ///
        /// A second collection rather than a second page of the first,
        /// because a body that read and wrote one interval would hold it
        /// once under the mode that subsumes the other — and the two
        /// modes are the point.
        ledger: Ordered<u64>,
        noted: Cell<u64>,
        /// A two-valued fact a body may store and read back.
        ///
        /// Here because a `bool` is a cell the vocabulary admits and
        /// nothing else in the corpus keeps one: a contract with a paused
        /// bit, a settled marker or a side chosen once wants exactly this
        /// leaf, and the shape a stored boolean has is a thing the
        /// grammar should record rather than leave to the first package
        /// that needs it.
        flagged: Cell<bool>,
        /// What each configured party is owed: one leaf per party, which
        /// is what a `for-each` declares a clause each of.
        owed: Keyed<u64>,
        /// What this instance has accrued of each configured asset,
        /// beside the vault it was taken from.
        ///
        /// A second family of vaults, because a movement wants somewhere
        /// to land that is not where it came from: one leaf keyed by the
        /// resource it holds, which is the one type a vault's key has.
        fees: Keyed<Vault>,
        /// The open family the movement grammar runs through: one vault
        /// per resource a body names.
        till: Keyed<Vault>,
        /// Custody over an open mark set: one collection of instances
        /// per resource a body names, which is the keyed mirror of the
        /// till beside it.
        stowage: Keyed<Instances>,
    }

    impl Grammar {
        /// A loop over a computed list, ending the body. Both halves
        /// matter: the loop is not a `for-each` because what it ranges
        /// over is not a term, and it is not a returned value because the
        /// method yields nothing however the tail is spelled.
        pub fn file(&mut self, ids: Ids) {
            // The whole space spelled as a range: what `all(64)` says in
            // one word, kept in the long form here.
            let mut held = self.entries.range(pack(0, 0), pack(u64::MAX, u64::MAX), 64);
            for id in ids.named().iter().copied() {
                held.insert(pack(0, id), Quantity::from_subunits(1));
            }
        }

        /// A `while` walking an interval by index, and a conditional in
        /// tail position — the other two ways a unit body ends.
        pub fn sweep(&mut self, holder: ResourceAddr) {
            let mut held = self.entries.all(64);
            let vault = self.till.at(holder);
            let mut index = 0;
            let mut total = vault.balance();
            while index < held.count() {
                total += held.entry(index);
                index += 1;
            }
            if !total.is_zero() {
                held.set(0, total);
            }
        }

        /// A branch the declaration can read, over a cell the code around
        /// it also reaches.
        ///
        /// The guard is a fact about the collection rather than about the
        /// line that first named it, so the clause is declared always and
        /// the guest takes no verdict — it branches on the condition it
        /// wrote. What the emission has to get right is that the handle
        /// is there on both arms: a body writing an entry conditionally
        /// and another unconditionally reaches one handle twice.
        pub fn settle(&mut self, seed: u64) {
            if seed == 1 {
                self.entries
                    .all(64)
                    .insert(OrderKey::at(0, 1), Quantity::from_subunits(1));
            }
            self.entries
                .all(64)
                .insert(OrderKey::at(0, 2), Quantity::from_subunits(2));
        }

        /// A branch whose arm alone declares its clause, so the export
        /// takes the declaration's verdict as a `bool` and the guest
        /// branches on that rather than on a second copy of the
        /// condition. The guarded shape `settle` deliberately avoids:
        /// nothing outside the arm reaches the handle, so the clause is
        /// conditional and the verdict crosses the boundary.
        pub fn stash(&mut self, seed: u64) {
            if seed == 1 {
                self.entries
                    .all(64)
                    .insert(OrderKey::at(0, 3), Quantity::from_subunits(3));
            }
        }

        /// A produced edge out of a conditional body, so the value path
        /// is exercised beside the statement ones.
        pub fn take(&mut self, resource: ResourceAddr, amount: Quantity) -> Bucket {
            self.till.at(resource).reserve(amount)
        }

        /// An edge and an answer out of one body.
        ///
        /// A method hands back at most one value and any number of
        /// edges, and the two are independent: an answer is not a third
        /// arity but a thing that happens beside whichever arity the
        /// method has. Here because the calling surface has to spell
        /// that as a pair, and a shape only the lowering admits is one
        /// the wrapper can get wrong unseen.
        pub fn take_noting(&mut self, resource: ResourceAddr, amount: Quantity) -> (Bucket, u64) {
            (self.till.at(resource).reserve(amount), self.noted.get())
        }

        /// A fielded mint beside the read of what it filed: one cell,
        /// written as the record the mark declares and decoded back as
        /// the same. Both halves are here because a host build settles
        /// the declaration for either order and says nothing about what
        /// the guest half writes.
        pub fn seat(&mut self, id: u64, holder: u64) -> NfBucket {
            let seated = Seat::mint(id, Seat { holder });
            if let Some(seat) = Seat::at(id) {
                self.noted.set(seat.holder);
            }
            seated
        }

        /// Arithmetic behind a closure, and the same arithmetic
        /// without one.
        ///
        /// A closure that opens no site and produces no edge is
        /// ordinary code: the value it folds is already in hand, so
        /// there is no access for a declaration to be missing. The two
        /// bodies are here together because what has to hold is that
        /// they declare the same thing.
        pub fn tally(&mut self, seed: u64) {
            let bumped = Some(seed).map(|held| held + 1);
            self.noted
                .set(bumped.unwrap_or_else(|| seed.wrapping_mul(3)));
        }

        /// [`Grammar::tally`] written the long way.
        #[allow(clippy::option_if_let_else)] // the long way is what the comparison is over
        pub fn tally_plainly(&mut self, seed: u64) {
            let bumped = Some(seed);
            let folded = match bumped {
                Some(held) => held + 1,
                None => seed.wrapping_mul(3),
            };
            self.noted.set(folded);
        }

        /// A configured table read where the declaration evaluates it.
        ///
        /// The bare lookup, which is the shape the guarded spelling in
        /// [`Grammar::charge_or`] exists to protect and which had no way
        /// to reach the guest of its own. A miss is a routing refusal,
        /// so a caller naming an unscheduled tier never runs this.
        pub fn charge(&mut self, tier: u64) {
            let fee = self.config().tiers.get(tier);
            self.noted.set(fee);
        }

        /// The same read, guarded on the question a miss answers.
        ///
        /// The selection is one value, so what crosses is the fee the
        /// declaration chose rather than the table and a comparison —
        /// and the untaken arm is never evaluated, which is what keeps
        /// the miss from refusing.
        pub fn charge_or(&mut self, tier: u64) {
            let terms = self.config();
            let fee = if terms.tiers.contains(tier) {
                terms.tiers.get(tier)
            } else {
                terms.fallback
            };
            self.noted.set(fee);
        }

        /// The question itself, in value position rather than as a
        /// guard: a judgment only the evaluator can answer, crossing as
        /// the flag a clause's verdict crosses as.
        pub fn scheduled(&mut self, tier: u64) {
            self.noted
                .set(u64::from(self.config().tiers.contains(tier)));
        }

        /// A projection of a product the body spelled itself.
        ///
        /// The pair never reaches the guest — a projection is evaluated
        /// where the declaration is — so what the export takes is the
        /// component, and the tuple is a spelling rather than a value.
        pub fn later(&mut self, first: u64, second: u64) {
            let pair = (first, second);
            self.noted.set(pair.1);
        }

        /// A macro whose arguments are expressions, walked like any
        /// others.
        ///
        /// `vec!` carries no syntax of its own, so each element is
        /// walked and re-emitted — a configured lookup and a state read
        /// inside one declare exactly as they would beside it, and an
        /// element holding neither comes out as itself.
        pub fn tallied(&mut self, tier: u64) {
            let mut fees = vec![self.config().tiers.get(tier), self.noted.get()];
            fees.push(1);
            self.noted.set(fees.iter().sum());
        }

        /// One clause per configured party, executed through the run
        /// its expansion materialises.
        ///
        /// What varies per element is the cell the clause names, which
        /// the declaration computed — so the body reaches the element as
        /// a key and never as a value, and what it writes is the amount
        /// it was called with. The loop the guest runs is the run's, and
        /// its width is the list the declaration mapped over.
        pub fn spread(&mut self, owed: u64) {
            for &side in &self.config().sides {
                self.owed.at(side).set(owed);
            }
        }

        /// The same loop with a guard inside it.
        ///
        /// The clause is declared for the elements the condition holds
        /// for and for no others, and the guest skips the rest on the
        /// verdict the run reports — the element it would have compared
        /// is evaluated where the declaration is, so a second copy of
        /// the condition is not something the guest could hold.
        pub fn spread_to(&mut self, owed: u64, only: Address) {
            for &side in &self.config().sides {
                if side == only {
                    self.owed.at(side).set(owed);
                }
            }
        }

        /// Value into the vault its own resource keys.
        ///
        /// What a survey needs there to be something to read: the
        /// denomination is the edge's, so the body names no resource and
        /// the leaf is the one the payment was in.
        pub fn fund(&mut self, funds: Bucket) {
            self.till.at(funds.resource()).put(funds);
        }

        /// What every configured asset's vault holds, summed into the
        /// cell.
        ///
        /// A read per element on a leaf that states what it holds, which
        /// materialises the amount read `spread`'s plain cells do not —
        /// so the run walked here carries a different mode from the one
        /// beside it, at the same width and the same indices.
        pub fn surveyed(&mut self) {
            let mut total = Quantity::ZERO;
            for &asset in &self.config().assets {
                total += self.till.at(asset).balance();
            }
            self.noted
                .set(u64::try_from(total.subunits()).unwrap_or(u64::MAX));
        }

        /// A fee out of every configured asset's vault, into the leaf
        /// beside it.
        ///
        /// Two sites under one loop, and the modes they materialise are
        /// what the bodies do rather than what they are spelled: the
        /// vault is read and moved, so it is an amount cell; the fee leaf
        /// is only moved into, so it is a delta. Two runs, two resource
        /// types at the boundary, and one index meaning one element in
        /// both.
        pub fn accrue(&mut self, fee: Quantity) {
            for &asset in &self.config().assets {
                let mut held = self.till.at(asset);
                // The read is what makes the site exclusive rather than
                // commutative: a body that took without looking would be
                // declaring a delta, which is the leaf beside it.
                let taken = held.balance().min(fee);
                self.fees.at(asset).put(held.take(taken));
            }
        }

        /// A hold on every configured asset's vault, taken as the grant
        /// it is and landed beside it.
        ///
        /// The site does nothing but reserve, which is the one shape a
        /// reservation has: feasibility was judged and the hold taken
        /// before this body ran, so there is no balance to read and no
        /// amount to name — the grant is the bucket. What it lands in is
        /// moved into and nothing else, so that site is a delta as it is
        /// under [`Grammar::accrue`].
        pub fn escrow(&mut self, hold: Quantity) {
            for &asset in &self.config().assets {
                let granted = self.till.at(asset).reserve(hold);
                self.fees.at(asset).put(granted);
            }
        }

        /// A line into one window's own log, at the order the caller
        /// named.
        ///
        /// Not a loop: what a run walks has to be there first, and a
        /// window is named rather than mapped over here.
        pub fn jot(&mut self, window: u64, at: u64) {
            self.entries
                .of(window)
                .all(8)
                .insert(OrderKey::at(0, at), Quantity::from_subunits(1));
        }

        /// What every configured window's log holds, and a line into the
        /// ledger beside each.
        ///
        /// Two interval runs under one loop: a collection is named by
        /// its owner, its slot and the material folded into it, so a
        /// sub-collection per element is a family of intervals and not a
        /// shape of its own. The page is named by literals rather than
        /// by the element — what varies per element is the collection,
        /// which the declaration computed.
        pub fn windowed(&mut self, note: u64) {
            let mut total = 0;
            for &window in &self.config().windows {
                let held = self.entries.of(window).all(8);
                total += u64::from(held.count());
                self.ledger
                    .of(window)
                    .all(8)
                    .insert(OrderKey::at(0, note), note);
            }
            self.noted.set(total);
        }

        /// How many lines the ledger holds for one named window.
        pub fn ledgered(&mut self, window: u64) -> u64 {
            u64::from(self.ledger.of(window).all(8).count())
        }

        /// A configured sequence read as the value it is, rather than
        /// mapped over.
        ///
        /// The list crosses as the numbers it holds, at the type the
        /// declaration named it — so a body may consult the very list a
        /// loop beside it maps over, and the two agree because they read
        /// one evaluation. Through a free function, because a `for` over
        /// a term is the declaration's loop rather than the guest's.
        pub fn widest(&mut self) {
            self.noted.set(largest(&self.config().windows));
        }

        /// File the instances an edge carries into this instance's own
        /// custody.
        pub fn stow(&mut self, instances: NfBucket) {
            self.stowage
                .of(instances.resource())
                .whole()
                .file(instances);
        }

        /// Every configured mark's instances, taken out of custody and
        /// filed back into it.
        ///
        /// The one interval mode that moves value: a custody interval
        /// is narrowed by the resource whose instances it holds, so a
        /// walk over the configured marks is a family of them. The take
        /// and the file at one site are one clause, and the cap the
        /// declaration derives is the walk those moves perform.
        pub fn restow(&mut self, ids: Ids) {
            for &mark in &self.config().marks {
                let held = self.stowage.of(mark).whole().take(ids.clone());
                self.stowage.of(mark).whole().file(held);
            }
        }

        /// A per-element amount, which is what a body reaching an
        /// element as a value is for.
        ///
        /// The element is read out of the very list the loop maps over,
        /// at the index the run is walked by — the two indices are one by
        /// construction, so the number a body reads and the leaf a clause
        /// beside it declared belong to the same element.
        pub fn owe_each(&mut self) {
            for &side in &self.config().windows {
                self.owed.at(side).set(side);
            }
        }

        /// A method that hands back an ordinary value.
        ///
        /// It produces no edge, so the declaration says it produces
        /// none; what it answers with rides the receipt, where whoever
        /// sent the transaction reads it. A manifest has nowhere to put
        /// one, which is what keeps a view function a view function.
        pub fn noted(&self) -> u64 {
            self.noted.get()
        }

        /// Raise the flag, and answer whether it was already up.
        ///
        /// No `bool` parameter, because a manifest binds none: a
        /// direction a caller chooses reads as two named methods, which
        /// is a better surface than an argument nobody can see the
        /// meaning of at the call site. What crosses *out* is a boolean
        /// like any other answer.
        pub fn raise(&mut self) -> bool {
            let was = self.flagged.get();
            self.flagged.set(true);
            was
        }

        /// The record changing under a live instance: the same cell the
        /// mint filed, written again where the mint required nothing to
        /// be. What never moves is the id, which is the instance's
        /// identity and is not in the record at all.
        pub fn reseat(&mut self, id: u64, holder: u64) {
            Seat::rewrite(id, Seat { holder });
            if let Some(seat) = Seat::at(id) {
                self.noted.set(seat.holder);
            }
        }

        /// The instances retiring: what the edge carries leaves
        /// circulation, and every cell that described one ends with it —
        /// so the ids are free for a later mint and the issuer's state
        /// falls back to what it was.
        ///
        /// The width is the edge's rather than this method's: a
        /// declaration clause per instance, and a guest that walks the
        /// run those expansions lend.
        pub fn unseat(&mut self, seat: NfBucket) {
            Seat::burn(seat);
        }

        /// The record of every instance an edge carries, summed into the
        /// cell — read once per instance, at a width the caller chose
        /// and the signature does not name.
        pub fn survey(&mut self, seats: NfBucket) -> NfBucket {
            let mut total = 0;
            for held in Seat::each(&seats) {
                total += held.holder;
            }
            self.noted.set(total);
            seats
        }

        /// The same record, read off the edge carrying the instance
        /// rather than at an id the caller named. The edge is handed
        /// back, so what the reading costs a holder is nothing — and
        /// what the declaration says about it is that it carries one
        /// seat, which an edge carrying any other number fails.
        pub fn seated(&mut self, seat: NfBucket) -> NfBucket {
            if let Some(held) = Seat::held(&seat) {
                self.noted.set(held.holder);
            }
            seat
        }
    }

    /// The largest of a configured sequence, over the list itself.
    fn largest(windows: &[u64]) -> u64 {
        windows.iter().copied().max().unwrap_or(0)
    }
}

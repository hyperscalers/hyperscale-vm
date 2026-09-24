//! The kernel cell families: the reserved roles the kernel and the
//! chain write under an owner's prefix, the keys that name them, and
//! the values they hold.
//!
//! Every family is self-describing: the value re-derives its own key,
//! so a reader holding nothing but the leaf can tell which family it
//! belongs to and when it stops being needed. The sweepable families
//! lead their key with the expiry's bucket, so one owner's cells for
//! one bucket are a contiguous range a sweep walks.

use hyperscale_hbor::{Hbor, from_slice, to_vec};
use hyperscale_vm_types::{
    ARTIFACT_GRACE_MS, Address, COMMITTED_GRACE_MS, CROSSING_GRACE_MS, IntentHash, LegShape,
    ResourceAddr, SubstateKey, SweepBucket, TxHash,
};

use crate::KERNEL_SLOT_BASE;
use crate::hash::Hasher;
use crate::intent::IntentHeader;
use crate::types::{SlotId, bucketed_child_key, child_key};

/// The kernel-reserved role of intent nullifier substates under an
/// account's prefix.
///
/// The top of the role space is the kernel's, as the bottom is the
/// protocol vocabulary's and the middle is where packages number from.
/// Every slot in this file sits in the kernel band, at or above
/// [`KERNEL_SLOT_BASE`], whatever owner it is keyed under.
pub const NULLIFIER_SLOT: SlotId = SlotId(0xFFFF);

/// The kernel-reserved role of escrow record substates under the
/// producing node's target.
///
/// What the shard issuing a crossing writes: the resource and the amount
/// that left it. The record is the memo a reclaim reads, which is why
/// nothing has to remember a diff. In the kernel band, though it sits
/// under a node's target: a package's instances hold it under the same
/// address as their own slots.
pub const ESCROW_RECORD_SLOT: SlotId = SlotId(0xFFFD);

/// The kernel-reserved role of crossing claim substates under the
/// claiming node's target, in the kernel band.
///
/// What the shard *taking* a crossing writes, on whatever terms the
/// record carries. The record says value was issued and never that it is
/// still available; this is what says it was taken, and it is what makes
/// exactly one of the consumer's claim and the producer's reclaim
/// happen.
///
/// One role for both kinds of crossing, because both are held on one
/// term: an answer stands for as long as the record it answers for does,
/// which is a fact about another chain rather than a clock. So it
/// outlives every window and carries the record it answers for.
pub const CROSSING_CLAIM_SLOT: SlotId = SlotId(0xFFFB);

/// The reserved role of crossing decline substates under the consuming
/// node's target, in the kernel band.
///
/// What the shard *refusing* a crossing writes: the consumer's one
/// negative answer, and the licence its producer credits the value back
/// on. Its one writer is the consuming member's own refusal receipt,
/// built by the host under the transaction's name, because a refused
/// member's own writes are discarded and a member that never ran writes
/// nothing at all, which is exactly the case a decline is for.
///
/// Its own role rather than its own value, so a producer asking which
/// answer it got asks two keys under one owner and reads a presence. A
/// reader holding the leaf still learns which it is from the value,
/// which is what re-derives this key.
///
/// The slot below it, `0xFFF9`, is retired and never reused.
pub const CROSSING_DECLINE_SLOT: SlotId = SlotId(0xFFFA);

/// The reserved role of committed-transaction substates under a shard's
/// own owner, in the kernel band.
///
/// What a shard writes at block commit for every transaction the block
/// carries: the fact that it committed it, provable and refutable
/// against the state root every header carries. No kernel writes one;
/// the chain does, and a reader holding nothing but the leaf can tell
/// it from any other cell and tell when it stops being needed.
pub const COMMITTED_TX_SLOT: SlotId = SlotId(0xFFFC);

/// The most bytes a [`Marker`] cell holds.
///
/// A nullifier or a committed cell: a transaction hash, an expiry and
/// what it marks. The width the declaration prices these cells at, held
/// to by the encoding pin beside the type.
pub const MARKER_CELL_BYTES: u32 = 96;

/// The most bytes a [`CrossingCell`] holds: the escrow record under a
/// producing node's target, on [`MARKER_CELL_BYTES`]'s terms.
pub const CROSSING_CELL_BYTES: u32 = 256;

/// The most bytes a [`CrossingAnswer`] cell holds, in either family.
///
/// Wider than [`MARKER_CELL_BYTES`] because it carries a whole
/// [`SubstateKey`] a marker does not: the record under the producing
/// node's target, which a consumer holding only its own answer could
/// never derive.
pub const CROSSING_ANSWER_CELL_BYTES: u32 = 160;

// Held at compile time rather than by a test: every side is a constant,
// so a kernel cell outside the kernel band — where a package could name
// it — or colliding with another kernel family is a thing the build can
// refuse outright. The nullifier is the top of the space, which no base
// can lie above.
const _: () = assert!(NULLIFIER_SLOT.0 == u16::MAX);
const _: () = assert!(ESCROW_RECORD_SLOT.0 >= KERNEL_SLOT_BASE);
const _: () = assert!(CROSSING_CLAIM_SLOT.0 >= KERNEL_SLOT_BASE);
const _: () = assert!(CROSSING_DECLINE_SLOT.0 >= KERNEL_SLOT_BASE);
const _: () = assert!(COMMITTED_TX_SLOT.0 >= KERNEL_SLOT_BASE);
const _: () = assert!(NULLIFIER_SLOT.0 != ESCROW_RECORD_SLOT.0);
const _: () = assert!(NULLIFIER_SLOT.0 != CROSSING_CLAIM_SLOT.0);
const _: () = assert!(ESCROW_RECORD_SLOT.0 != CROSSING_CLAIM_SLOT.0);
const _: () = assert!(CROSSING_DECLINE_SLOT.0 != CROSSING_CLAIM_SLOT.0);
const _: () = assert!(CROSSING_DECLINE_SLOT.0 != ESCROW_RECORD_SLOT.0);
const _: () = assert!(CROSSING_DECLINE_SLOT.0 != NULLIFIER_SLOT.0);
const _: () = assert!(COMMITTED_TX_SLOT.0 != NULLIFIER_SLOT.0);
const _: () = assert!(COMMITTED_TX_SLOT.0 != ESCROW_RECORD_SLOT.0);
const _: () = assert!(COMMITTED_TX_SLOT.0 != CROSSING_CLAIM_SLOT.0);
const _: () = assert!(COMMITTED_TX_SLOT.0 != CROSSING_DECLINE_SLOT.0);

/// The canonical nullifier key for a signed intent under one of its
/// accounts:
/// `account_prefix | expiry_bucket | H(nullifier_role, intent_hash,
/// expiry)`.
///
/// The expiry is part of the identity rather than only of the value, so
/// a spend cannot claim a life the declaration does not give it: the key
/// a false expiry names is not the key the screen expects, and the
/// declaration does not cover it.
///
/// It is in the identity twice over — hashed into the body and, coarsely,
/// leading the local half — so a nullifier answers *when* it stops being
/// needed from its key alone, and one account's nullifiers for one
/// bucket are a contiguous leaf-key range for a sweep to walk. Both halves come
/// from the one `expiry_ms` argument, so neither can drift from the
/// other.
#[must_use]
pub fn nullifier_key(
    hasher: &dyn Hasher,
    account: impl Into<Address>,
    intent: IntentHash,
    expiry_ms: u64,
) -> SubstateKey {
    bucketed_child_key(
        hasher,
        account,
        NULLIFIER_SLOT,
        SweepBucket::of(expiry_ms),
        &[intent.0.0.to_vec(), expiry_ms.to_le_bytes().to_vec()],
    )
}

/// The canonical committed-transaction key for `tx` under the committing
/// shard's own owner: `shard_prefix | expiry_bucket | H(committed_tx_role,
/// tx, expiry)`.
///
/// Bucketed like the nullifier, so a shard's committed set for one
/// bucket is a contiguous range a sweep walks, and self-describing like
/// it, so a leaf answers when it stops being needed on its own. The
/// expiry is the transaction's own validity end plus the grace, which a
/// reader derives from signed content: a prober asking whether a shard
/// committed a transaction needs nothing but the transaction and the
/// shard to name the cell.
///
/// The material here is chosen by a composer and not by the owner,
/// which [`bucketed_child_key`] warns against on its 48-bit birthday
/// bound. It is admissible for this family because a live committed
/// cell always names the transaction that created it: a block carries
/// no transaction whose committed key is present in its parent state or
/// named by another transaction in the same block, refused at
/// validation and deferred by the proposer, so a retraction keyed by an
/// attested outcome deletes that transaction's cell and no other, and a
/// leaf read absent was never written for the transaction asked about.
/// A composer who grinds a collision defers only his own second
/// transaction.
#[must_use]
pub fn committed_tx_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    tx: TxHash,
    expiry_ms: u64,
) -> SubstateKey {
    bucketed_child_key(
        hasher,
        owner,
        COMMITTED_TX_SLOT,
        SweepBucket::of(expiry_ms),
        &[tx.0.0.to_vec(), expiry_ms.to_le_bytes().to_vec()],
    )
}

/// The canonical escrow record key for one value edge, under the
/// producing node's target.
///
/// Keyed by what its signer signed and by nothing the composition
/// chose. `intent` is the declaration hash of the intent the producing
/// node belongs to and `local` is that node's index inside it — never
/// the transaction hash and never the flattened manifest index, both of
/// which a composer who is not this cell's owner assembles.
///
/// That is what admits the bucketed form here. It spends four of the
/// local half's sixteen bytes, so what is left is a 96-bit owner-salted
/// body and a 48-bit birthday bound — affordable only where both halves
/// of a collision need one signer's signature, which is exactly what
/// keying by the signing intent restores. Two escrow cells a grinder can
/// collide are then two whose material the grinder chose, and reaching
/// somebody else's is a second preimage again.
///
/// The expiry is not in the identity at all, which is what separates
/// this family from the sweepable ones: they lead their local half with
/// the bucket their expiry falls in, and a key carrying no bucket is one
/// no sweep can walk to. The edge alone names the record, and the record
/// states its own expiry in its value, where it is the anchor a presence
/// is asked from rather than a life.
#[must_use]
pub fn escrow_record_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    intent: IntentHash,
    local: u32,
    output: u32,
) -> SubstateKey {
    child_key(
        hasher,
        owner,
        ESCROW_RECORD_SLOT,
        &[
            intent.0.0.to_vec(),
            local.to_le_bytes().to_vec(),
            output.to_le_bytes().to_vec(),
        ],
    )
}

/// The canonical crossing claim key for one value edge, under the target
/// of the node that took it.
///
/// The same material as [`escrow_record_key`] under a different owner
/// and a different role, which is what lets one crossing be named by
/// both shards without either consulting placement. The owner is what
/// distinguishes two consumers of one output; the role is what keeps a
/// claim from ever aliasing the record it claims.
///
/// Unbucketed for the same reason the record is: the expiry is not in
/// the identity, because nothing sweeps the cell. What ends a claim is
/// the producer disposing of the record it names, which is a fact about
/// another chain rather than a clock.
#[must_use]
pub fn crossing_claim_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    intent: IntentHash,
    local: u32,
    output: u32,
) -> SubstateKey {
    answer_key(hasher, owner, CROSSING_CLAIM_SLOT, intent, local, output)
}

/// The canonical crossing decline key for one value edge, under the
/// target of the node that refused it.
///
/// [`crossing_claim_key`] under the other role, on the same material and
/// the same owner. Two keys rather than one cell with two meanings,
/// because what a producer asks is whether a cell is *there* — a proof
/// of presence carries a value hash and nothing a reader could compare
/// against without pinning an encoding, so the key is what says which
/// answer was given.
#[must_use]
pub fn crossing_decline_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    intent: IntentHash,
    local: u32,
    output: u32,
) -> SubstateKey {
    answer_key(hasher, owner, CROSSING_DECLINE_SLOT, intent, local, output)
}

fn answer_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    slot: SlotId,
    intent: IntentHash,
    local: u32,
    output: u32,
) -> SubstateKey {
    child_key(
        hasher,
        owner,
        slot,
        &[
            intent.0.0.to_vec(),
            local.to_le_bytes().to_vec(),
            output.to_le_bytes().to_vec(),
        ],
    )
}

/// What an escrow record cell holds: the value that left, the edge it
/// left on, when it stops being claimable, and who issued it.
///
/// Self-describing on [`Marker`]'s terms: the value re-derives the
/// key, so a reader holding nothing but the leaf can tell what it is.
/// Unlike the sweepable families the key carries no bucket, so re-deriving
/// it is all a reader gets — a record is not sweepable and no expiry in
/// the key could make it so.
///
/// The edge is named here as well as in the key because a reclaim reads
/// this cell and nothing else — the producing shard credits the resource
/// and the amount back from the leaf alone, holding no transaction body
/// and no window of them. So is the cell the value left: a reclaim
/// credits it, and no rule the kernel could hold says which of an owner's
/// cells that is — an account's vault for a resource is the account
/// package's own layout, and a component's is another.
///
/// The expiry, the issuing transaction and the consumer's claim are
/// terms of the reclaim rather than the record's identity, which stays
/// the edge the key is derived from. The transaction is what a
/// successor's reclaim is admitted under, the tick and its receipt being
/// keyed by transaction and a record naming none being unadmittable. The
/// consumer's claim is the cell that decides between the two housekeeping
/// members a record ends in: present says the crossing was taken and the
/// record is the retirement's, absent past the lapse says it was not and
/// the value is the producer's to credit back. Nothing else names it —
/// its owner is the consuming node's target, which lives in the manifest
/// and not in the leaf — so a holder of the record and no body could not
/// derive it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct CrossingCell {
    /// The resource that crossed.
    pub resource: ResourceAddr,
    /// How much of it.
    pub amount: u128,
    /// The signed intent the producing node belongs to.
    pub intent: IntentHash,
    /// That node's index within its own intent.
    pub local: u32,
    /// Which of its outputs the edge carried.
    pub output: u32,
    /// The producing intent's own window end plus [`CROSSING_GRACE_MS`] —
    /// the intent's, not the transaction's, so the composer chooses no
    /// part of it.
    ///
    /// What it names depends on the terms. For an escrowed crossing it is
    /// when no chain can still be claiming: the sweep of the claim cell
    /// the record is decided against, keyed by this same figure so the
    /// two agree. For an owed one nothing sweeps, so what is left of it
    /// is the deadline a reader recovers from it — the anchor a presence
    /// is asked from, and not a life.
    pub expiry_ms: u64,
    /// The transaction whose execution issued the crossing.
    pub tx: TxHash,
    /// The claim cell the consumer writes when it takes the crossing,
    /// under the consuming node's target.
    ///
    /// Which family it sits in follows from [`Self::terms`]: an escrowed
    /// crossing's answer is a witness swept at this record's `expiry_ms`,
    /// which is where a reader's window to judge it absent closes; an
    /// owed one's is swept by nothing, so its absence closes no window
    /// and answers nothing at any clock.
    pub consumer_claim: SubstateKey,
    /// What kind of record this is, and the terms that kind carries.
    /// Resolved by the kernel at the issue.
    pub terms: Terms,
}

/// Which kind of crossing a departure writes, and so which family its
/// consumer's answer sits in.
///
/// The parent reads it off the shape — a crossing an outbound leg
/// consumes is owed, and every other one is escrowed — and the kernel
/// turns it into the record's own [`Terms`] at the issue, where it knows
/// what the value came off and so what an escrowed one credits back.
/// Two types for one distinction because only the second half of it can
/// carry that cell, and only the first half can key one: a claim's key
/// is derived before any execution knows what a reclaim would credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Staged against a verdict that has not happened: the producer
    /// keeps the cell the value left and takes the crossing back where
    /// no consumer claims it.
    Escrowed,
    /// Owed to its consumer by a verdict that has: no cell is the
    /// crossing's to return to, and nothing takes it back.
    Owed,
}

/// What a crossing record is: value staged against a verdict that has
/// not happened, or value a verdict already moved.
///
/// The two agree on almost nothing. An escrowed crossing has an owner
/// and comes home where no consumer claims it; an owed one has neither,
/// and stands until its consumer takes it. Which disposals are possible,
/// which readings answer, what a clock may do to it — all of it follows
/// from which of the two a record is, so the record says so rather than
/// leaving every reader to work it out again.
///
/// Resolved once, at the issue, and carried on the record: what outlives
/// the manifest is the leaf, and the member that settles a record may
/// hold nothing else — a split child, or a reshape successor whose store
/// arrives as a prefix of leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum Terms {
    /// Staged against a verdict that has not happened.
    Escrowed {
        /// The cell the value left, which a reclaim credits.
        credit: SubstateKey,
    },
    /// Owed to its consumer by a verdict that has. A crossing an
    /// outbound leg consumes is that consumer's from the moment the core
    /// commits it, so no cell is the crossing's to return to and the
    /// record stands until the claim retires it.
    Owed,
    /// Disposed of, and standing only so its going can be dated.
    ///
    /// **A tombstone, and the one cell in this family whose life is a
    /// life.** The value is gone — credited back or moved where the
    /// consumer's claim ran — so nothing can be built from it and no
    /// delivery can run off it. What the key is still doing there is
    /// carrying a clock: a consumer deletes its answer once no bundle
    /// for the record can still be admitted, and it reads the record
    /// rather than remembering it, because a proof carries a value hash
    /// and never a value. An absence is the one thing a proof can say
    /// plainly, so the producer holds the key for
    /// [`CROSSING_TOMBSTONE_GRACE_MS`](hyperscale_vm_types::CROSSING_TOMBSTONE_GRACE_MS)
    /// past the disposal and then takes it away. The going of it is the
    /// date.
    ///
    /// [`CrossingCell::expiry_ms`] names that instant here, which is
    /// the one term this variant changes: for the other two it is read
    /// off the producing intent's window, and for this one off the
    /// disposal, because the disposal is what it is a grace on.
    Retired,
}

impl Terms {
    /// Which kind of crossing these terms are the terms of, for terms
    /// that are still a crossing's.
    ///
    /// The half a claim's key reads, where the whole is what a reclaim
    /// credits. [`Self::Retired`] has no kind and answers `None`: the
    /// crossing it was the terms of is over, and a caller reaching for
    /// a kind is asking about a live edge.
    #[must_use]
    pub const fn kind(self) -> Option<Kind> {
        match self {
            Self::Escrowed { .. } => Some(Kind::Escrowed),
            Self::Owed => Some(Kind::Owed),
            Self::Retired => None,
        }
    }
}

impl CrossingCell {
    /// The cell's committed bytes.
    ///
    /// # Panics
    ///
    /// Never: the value is scalars and one address.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("a crossing cell is scalars and an address")
    }

    /// A record read back off the leaf, or nothing for bytes that are
    /// not one — the type owns its decoding for the reason it owns its
    /// encoding.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        from_slice(bytes).ok()
    }
}

/// What a marker cell holds: which transaction wrote it, when it stops
/// being needed, and which family it belongs to.
///
/// Two families share this one value, and each is self-describing on
/// the same terms: the value re-derives the cell's own key under the
/// family's role, so a reader holding nothing but the leaf can tell a
/// marker from any other cell, tell which family it is, and tell whether
/// it is still owed. The key leads with the expiry's bucket, so a shard's
/// markers for one bucket are a contiguous range a sweep walks, and
/// [`Marker::key`] is the one derivation every writer and every reader
/// agree by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct Marker {
    /// The transaction that wrote it.
    pub tx: TxHash,
    /// When the marker stops being owed: its intent's validity end plus
    /// its family's own grace, on that family's own terms.
    pub expiry_ms: u64,
    /// The fact the marker records.
    pub marks: Marked,
}

/// The fact a marker records, and so the family it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Marked {
    /// An intent was spent, under one of its accounts' prefix
    /// ([`nullifier_key`]): what makes a committed intent once-only,
    /// and what a signer writes to cancel one.
    Spent(IntentHash),
    /// The shard committed the transaction, under the shard's own owner
    /// ([`committed_tx_key`]): what a leg proves absent to show its core
    /// never included the transaction.
    Committed,
}

impl Marked {
    /// When a cell of this family stops being owed, for one derived from
    /// a signed window ending at `validity_end_ms`.
    ///
    /// The one place the families' lives are stated, so a writer cannot
    /// give a cell a life its family does not have — the same discipline
    /// [`Marker::key`] enforces on the key, one level up. A grace each,
    /// because each answers a different reader over a different span,
    /// and the argument for every one of them is at its own constant.
    #[must_use]
    pub const fn expiry_ms(self, validity_end_ms: u64) -> u64 {
        validity_end_ms.saturating_add(match self {
            Self::Spent(_) => ARTIFACT_GRACE_MS,
            Self::Committed => COMMITTED_GRACE_MS,
        })
    }
}

impl Marker {
    /// The marker `marks` for `tx`, owed until its own family's grace
    /// past the signed window it was derived from.
    ///
    /// The expiry is derived rather than taken, so the family and the
    /// life it is written with cannot come apart.
    #[must_use]
    pub const fn of(tx: TxHash, validity_end_ms: u64, marks: Marked) -> Self {
        Self {
            tx,
            expiry_ms: marks.expiry_ms(validity_end_ms),
            marks,
        }
    }

    /// The cell this marker sits at under `owner`: the family's own key,
    /// re-derived from what the value says.
    #[must_use]
    pub fn key(&self, hasher: &dyn Hasher, owner: impl Into<Address>) -> SubstateKey {
        match self.marks {
            Marked::Spent(intent) => nullifier_key(hasher, owner, intent, self.expiry_ms),
            Marked::Committed => committed_tx_key(hasher, owner, self.tx, self.expiry_ms),
        }
    }

    /// The cell's committed bytes.
    ///
    /// The type owns its encoding, so the writer of one and a reader
    /// deciding what it is agree by construction rather than by two
    /// call sites staying in step.
    ///
    /// # Panics
    ///
    /// Never: the value is scalars.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("a marker is scalars")
    }

    /// A marker read back off the leaf, or nothing for bytes that are
    /// not one.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        from_slice(bytes).ok()
    }
}

/// Which answer a consumer gave a crossing, and so which role its cell
/// sits under.
///
/// Both are the consuming member's own terminal event: a claim is
/// written inside the session that took the value, and a `Never` by
/// the member's refusal receipt, built by the host under the
/// transaction's name, when the member is refused. The two are
/// exclusive by construction rather than by agreement — the kernel
/// refuses a take where a `Never` stands, and a refused member's writes
/// never include a claim — and a record holding both would license a
/// retirement and a reclaim of one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Answered {
    /// The consumer took the crossing. The value is where it ran, and
    /// the producer's record is a retirement's.
    Taken,
    /// The consumer will never take the crossing. Its member was
    /// refused, and the value is the producer's to credit back.
    ///
    /// Only where the consumer's verdict is final — which is what
    /// [`Terms`] says, and the reason a delivery may not write one: a
    /// delivery that failed decides nothing, and the crossing behind it
    /// stands for a later attempt.
    Never,
}

impl Answered {
    /// The role a cell recording this answer sits under.
    #[must_use]
    pub const fn slot(self) -> SlotId {
        match self {
            Self::Taken => CROSSING_CLAIM_SLOT,
            Self::Never => CROSSING_DECLINE_SLOT,
        }
    }
}

/// What a crossing answer cell holds: which transaction answered the
/// crossing, which edge it was, which way the answer went, and the
/// record on the producer's chain it answers for.
///
/// Self-describing on the record's terms rather than a marker's: the
/// value re-derives the cell's own key under its answer's own role, so a
/// reader holding nothing but the leaf can tell it from any other cell
/// and tell which answer it is. What it cannot re-derive is `record`,
/// whose owner is the *producing* node's target and lives in the
/// manifest rather than in either leaf — so it is carried, and carrying
/// it is the whole reason this family exists. A consumer holding only
/// the material would have the edge and not the shard.
///
/// One type for both answers because they carry the same terms and are
/// cleaned up against the same record; two roles because what a producer
/// asks is which cell is *there*, and a key is what can answer that
/// without a reader pinning an encoding.
///
/// No expiry, because nothing sweeps it. A crossing is answered once, by
/// a presence its producer reads at whatever anchor it reaches, and this
/// cell is what refuses a second answer, so a clock that took it away
/// would license the second.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct CrossingAnswer {
    /// The transaction whose execution answered the crossing, or — for a
    /// decline — the one whose members will never run it.
    pub tx: TxHash,
    /// The signed intent the producing node belongs to.
    pub intent: IntentHash,
    /// That node's index within its own intent.
    pub local: u32,
    /// Which of its outputs the edge carried.
    pub output: u32,
    /// The record cell this answer answers for, under the producing
    /// node's target.
    pub record: SubstateKey,
    /// Which way the answer went.
    pub answered: Answered,
}

impl CrossingAnswer {
    /// The cell this answer sits at under `owner`: its own role's key,
    /// re-derived from what the value says.
    #[must_use]
    pub fn key(&self, hasher: &dyn Hasher, owner: impl Into<Address>) -> SubstateKey {
        answer_key(
            hasher,
            owner,
            self.answered.slot(),
            self.intent,
            self.local,
            self.output,
        )
    }

    /// The cell's committed bytes.
    ///
    /// # Panics
    ///
    /// Never: the value is scalars and a key.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("an answer is scalars and a key")
    }

    /// The answer a committed cell holds, or `None` where the bytes are
    /// not one.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        from_slice(bytes).ok()
    }
}
/// One escrow cell: where it sits, and what identifies it.
///
/// The key and the fields that derive it, built together so the two
/// cannot disagree. That matters because a sweepable cell answers *when
/// do I stop being needed* from its own value — the sweep re-derives the
/// key from what the leaf holds — so a cell whose value does not
/// reproduce its key is one no sweep ever reaches, which is a leak
/// nothing announces.
///
/// The kernel is handed these rather than deriving them. Its hashing
/// seam takes bytes and not a domain, so it could not derive a child key
/// if it wanted to; and deriving one is the parent's job anyway, since
/// two shards divide one manifest separately and have to reach the same
/// cell without consulting each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrossingSite {
    key: SubstateKey,
    intent: IntentHash,
    local: u32,
    output: u32,
    expiry_ms: u64,
}

impl CrossingSite {
    /// The record cell of the edge `local` produces, under the producing
    /// node's target.
    #[must_use]
    pub fn record(
        hasher: &dyn Hasher,
        owner: impl Into<Address>,
        intent: IntentHash,
        local: u32,
        output: u32,
        expiry_ms: u64,
    ) -> Self {
        let owner = owner.into();
        Self {
            key: escrow_record_key(hasher, owner, intent, local, output),
            intent,
            local,
            output,
            expiry_ms,
        }
    }

    /// The record cell of the edge `producer` leaves on `output`: under
    /// its target, keyed by what its own signer signed.
    #[must_use]
    pub fn record_of(hasher: &dyn Hasher, producer: &LegShape, output: u32) -> Self {
        Self::record(
            hasher,
            producer.target,
            producer.intent,
            producer.local,
            output,
            producer.expiry_ms,
        )
    }

    /// The claim cell for the edge `producer` leaves on `output`, under
    /// `owner`, the consuming node's target.
    #[must_use]
    pub fn claim_of(
        hasher: &dyn Hasher,
        owner: impl Into<Address>,
        producer: &LegShape,
        output: u32,
    ) -> Self {
        Self::claim(
            hasher,
            owner,
            producer.intent,
            producer.local,
            output,
            producer.expiry_ms,
        )
    }

    /// The claim cell for that edge, under the target of whatever takes
    /// it.
    ///
    /// One family whatever the record's terms, because both kinds of
    /// answer are held on one term: a claim stands while the record it
    /// answers for does. So it carries no bucket and no sweep reaches it.
    #[must_use]
    pub fn claim(
        hasher: &dyn Hasher,
        owner: impl Into<Address>,
        intent: IntentHash,
        local: u32,
        output: u32,
        expiry_ms: u64,
    ) -> Self {
        let owner = owner.into();
        Self {
            key: crossing_claim_key(hasher, owner, intent, local, output),
            intent,
            local,
            output,
            expiry_ms,
        }
    }

    /// Where the cell sits.
    #[must_use]
    pub const fn key(&self) -> SubstateKey {
        self.key
    }

    /// When it stops being owed.
    #[must_use]
    pub const fn expiry_ms(&self) -> u64 {
        self.expiry_ms
    }

    /// The record's value, once the execution knows what crossed and
    /// which transaction issued it.
    #[must_use]
    pub const fn crossing(
        &self,
        tx: TxHash,
        resource: ResourceAddr,
        amount: u128,
        consumer_claim: SubstateKey,
        terms: Terms,
    ) -> CrossingCell {
        CrossingCell {
            resource,
            amount,
            intent: self.intent,
            local: self.local,
            output: self.output,
            expiry_ms: self.expiry_ms,
            tx,
            consumer_claim,
            terms,
        }
    }

    /// The claim's committed bytes: which transaction took the crossing,
    /// on this edge, and the record it answers for.
    ///
    /// The record is named because the cell outlives every structure
    /// that could tell a reader where it sits — its owner is the
    /// *producing* node's target, which lives in the manifest and in
    /// neither leaf.
    #[must_use]
    pub fn claimed_by(&self, tx: TxHash, record: SubstateKey) -> Vec<u8> {
        self.answered_by(tx, record, Answered::Taken)
    }

    /// The answer's committed bytes, for either verdict: which
    /// transaction answered the crossing, on this edge, which way, and
    /// the record it answers for.
    #[must_use]
    pub fn answered_by(&self, tx: TxHash, record: SubstateKey, answered: Answered) -> Vec<u8> {
        CrossingAnswer {
            tx,
            intent: self.intent,
            local: self.local,
            output: self.output,
            record,
            answered,
        }
        .to_bytes()
    }

    /// The cell this claim site's edge is answered at in `answered`'s
    /// role, under the site's owner: the site's own key for a take, and
    /// the decline key on the same material for a `Never`.
    ///
    /// The one derivation of the decline key from an edge, so the
    /// member's refusal receipt, the abandonment and every reader name
    /// one cell.
    #[must_use]
    pub fn answer_key(&self, hasher: &dyn Hasher, answered: Answered) -> SubstateKey {
        match answered {
            Answered::Taken => self.key,
            Answered::Never => {
                crossing_decline_key(hasher, self.key.owner, self.intent, self.local, self.output)
            }
        }
    }
}

/// When an intent's nullifier stops being owed: the window its signer
/// signed, plus the grace [`Marked::Spent`] takes.
///
/// The intent's own window rather than the transaction's, for two
/// reasons that are one: the transaction's window is the intersection
/// of every intent's, so this is never earlier than it; and the
/// transaction's window is the composer's to choose, where a key has to
/// be made of nothing the composer chose.
#[must_use]
pub const fn nullifier_expiry_ms(header: &IntentHeader) -> u64 {
    header.validity_end_ms.saturating_add(ARTIFACT_GRACE_MS)
}

/// When the escrow cells of every node an intent holds stop being owed:
/// the window its signer signed, plus the grace [`CROSSING_GRACE_MS`]
/// takes.
///
/// The intent's own window, on [`nullifier_expiry_ms`]'s terms and for
/// the same two reasons. The grace differs because the families do: a
/// nullifier is answered on its own chain, and a crossing is decided
/// across a reshape cut.
#[must_use]
pub const fn crossing_expiry_ms(header: &IntentHeader) -> u64 {
    header.validity_end_ms.saturating_add(CROSSING_GRACE_MS)
}

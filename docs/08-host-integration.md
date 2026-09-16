# Host integration: the contract between engine and protocol

The engine is embedded by a sharded BFT host that commits transactions before executing them, transfers state between shards as merkle-proven provisions, and finalizes cross-shard transactions by unanimous execution certificates. This document states what the engine's design requires of that host and what it hands back — the boundary at which the `INV-VM-*` register meets the host's own invariant families (documented in the hyperscale-rs repository's `docs/`).

## 1. Provisions carry the read set and nothing else

A provision bundle needs to carry only what a counterpart must *read*: fresh-read values and the prior values of read-modify-write keys ([01-effects-and-routing.md](01-effects-and-routing.md) §3). A `delta` reads nothing; a `reserve`'s feasibility is judged at the owning shard; a blind `write` needs no prior value. Legs composed of commutative effects provision nothing and dispatch immediately.

An empty bundle is still emitted, because the same wire edge does a second job: it is **engagement evidence**. A counterpart engages a cross-shard transaction only against evidence that the shard paying its fee committed it, and every other participant echoes its own commitment back to the payer the same way (§2).

## 2. Cross-shard fee assurance

Fee payment is a `reserve` on the payer's vault, so the payer's shard is a participant by routing; what needs sequencing rules is that counterpart shards commit independently and would otherwise engage locks and burn work before learning the reservation is feasible — the insolvent-payer griefing vector. Three rules close it:

1. **Reservation at the payer's shard is a block-validity condition.** The signed `max_fee` must cover what the declaration prices to, or the payer's shard does not commit the transaction at all — and that ceiling is judged by the payer's shard and by no other, since fees never move cross-shard and two shards whose blocks sit either side of an epoch fold would name two tables. Feasibility is deterministic (committed balance minus prior reservations, hash-ordered), so payer insolvency after commitment is impossible by reservation semantics.

   What a block budgets is the declared vector, capped per dimension on the block's own content; what bounds how *many* transactions are in flight is a separate count, because every block is already capped per dimension and a full pipeline can owe at most three block caps by construction. Weight and number are two questions and the host answers them separately rather than folding a fixed per-transaction term into a quantity that is otherwise physical.
2. **Commit-proof-gated engagement.** A non-payer participant admits the transaction to a proposal — engaging locks, starting its deadline clock — only against a commit proof of the payer shard's block containing it, checked at vote as a validity rule so a Byzantine proposer cannot grief its own shard with unpayable transactions (INV-VM-HOST-1). The payer's shard commits first and the finalization deadline anchors on its commit. A certified-but-uncommitted payer block engages nothing.
3. **Fees never move cross-shard: burn locally, compensate by what was charged.** The declaration's price burns at the payer's shard on every outcome, written inside the settling receipt (INV-VM-HOST-2) — there is no surplus to release, because the price is the declaration's rather than a measurement's. Non-payer participants are compensated the way storage is: each shard's certificates carry what it charged for the transactions they settle, that total crosses into the host's fold through the same witness channel as the attested stored-byte totals ([03-objects-and-state.md](03-objects-and-state.md) §3), and the fold reweights the fixed per-epoch emission by both.

   The weight is the **fee** and not the fuel, which is what makes it unforgeable: a price is a pure function of signed content, so a proposer inflating its shard's emission has to inflate transactions its own committee admitted and priced, rather than a figure its engine reported about itself. No fee transfer, no netting protocol. Burns discipline users; emission-farming by self-dealing traffic spends real burned fees, so the burn-to-emission ratio is the sybil defense.

   **One table, and the host moves it.** The price of each dimension is a consensus value carried on the beacon, frozen a window ahead like the committee and read at the anchor a block already resolved — so a transaction straddling a fold is priced once rather than twice. The level inside governed bounds is a controller's: each epoch the fold moves each row by that dimension's own utilization across the shards whose boundary advanced, an eighth of the way at saturation and back at idle. Governance votes the bounds, demand picks the point inside them, and neither alone can price a block. The mean is deliberately blind to one hot shard among idle ones: placement is the protocol's choice, so a hotspot is answered with capacity — the shard splits on its own sustained load — rather than by billing the addresses that landed on it.

A reservation is an accounting entry over the payer shard's own committed chain, never an on-chain hold — release is the entry ceasing to be derivable, and under payer-shard termination there is nothing to inherit and nothing to sweep ([03-objects-and-state.md](03-objects-and-state.md) §7). A composition has exactly one fee payer, its own, because per-intent payers would create circular commit-proof dependencies among multiple first-committing shards; an intent reimburses the payer in-band, by a bounded edge inside the transaction rather than by a fee term of its own.

**The payer's vote is echo-gated.** The payer shard's committee votes once per cross-shard transaction, on a condition that is a pure function of its own chain: the success vote exists only with every counterpart's engagement echo committed on the payer's chain; past the transaction's validity window without full echo coverage, the committee's single statement is the all-abort vote carrying the fee record (INV-VM-HOST-3). The payer never resolves a transaction on a local timer after speaking, so no verdict splits.

Griefing residual, on record: the payer's shard can commit and reserve while a counterpart never commits; the deadline abort's floor fee must cover a full participant's wasted cycle.

**Rejected: exchange-rate-pegged pricing.** A ledger-state exchange rate is an exogenous oracle input into consensus pricing; every other quantity in this economics is endogenous and fold-derived. Token-denominated prices are governance-adjustable if they drift.

## 3. Authority: what the host may rely on

The authority model is [06-authority.md](06-authority.md); what a host needs from it is that its verdicts land in different places, that the earliest is free, and that the one reading an account's own cell lands before any body runs.

**Presence is reachable at admission, with no state read** (INV-VM-AUTH-1). Whether a call presents evidence where its target requires some is a pure function of signed content and content-addressed package metadata, so a scheduler can reach the verdict ahead of ordering and fee exposure: an envelope that presents nothing where something is required never enters a block and nobody pays for it. Every claim a node presents is produced inside its own intent, or arrives through a socket that intent declared and its composer filled from a claim the composer held in scope — so the resolution is still a read-off of the signed tree, and no shard reads the question differently.

**The sign-in lands at materialization, on the account's own shard** (INV-VM-AUTH-6). Admission resolves a signature to a claim on the account its intent acts as, and injects beside it a read of that account's `auth` cell and one condition: the rule there admits the attesting keys. The shard keeping the cell judges it before any body of the transaction runs, on the same terms as a presence condition — so a host schedules it with the rest of materialization and needs nothing new. Every account an intent acts as sits on a shard running an issuing member, or the shape runs whole (INV-VM-AUTH-7's placement half), which is what keeps the judgment ahead of the core rather than behind an outbound leg.

**Satisfaction needs the target's own state, so it lands at execution** (INV-VM-AUTH-2). Every claim a method can require is one the target itself names, and every cell a gate reads is one the method's own declaration carries — so the verdict is provisioned by the ordinary read-set machinery of §1 and never reaches state under a prefix the manifest did not name. A call presenting too little aborts identically on every replica and its sender pays the ceiling they signed.

One consequence the host relies on elsewhere: the payer shard's fee-binding check reads the same cell through the same verdict function as the injected sign-in. They ask different questions — may this key spend from the payer's vault, and may it act as this account — but neither can read the cell differently from the other, so who may spend from an account and who may act as it cannot come apart.

## 4. What the host provides the environment

- **The transaction clock**: the canonical weighted-time anchor of the payer-shard block that committed the transaction, carried by the same commit proof §2 requires — one value per transaction, identical on every participant ([04-execution-semantics.md](04-execution-semantics.md) §3).
- **Epoch**: the epoch the payer block's clock falls in. The kernel stamps it into a cell a transaction seals; no guest reads it, and none names one.
- **Seeds**: the beacon's rolled seeds for the epochs still inside the retained window, from the reveal fold alone. What a matured seal resolves against; the ceremony's are left out, since a beacon member could have withheld from one.
- **Nothing else.** No shard-local time, no schedule position, no per-execution entropy (INV-VM-RUN-1).

## 5. What the engine hands back

- **Shard-invariant outputs.** Execution projects to a form every participant derives identically — receipt hash, events, outcome — with only the database writes filtered per shard by ownership. All failures collapse to one canonical failed-receipt hash.
- **Events as consensus content.** Blueprint-declared, typed by the package's own event table, size- and count-capped, carried success-only, homed on the emitting object's shard — a multi-shard transaction's events ride only their emitters' receipts — and merkled into the receipt root. The host's beacon witness channel consumes the staking component's events from its home shard.
- **The fee attested.** Each finalized tick's outcomes carry what the shard charged for the transactions they settle — the price of its own share of each declaration, at the table its committing block named — which is what the emission reweighting in §2 consumes. What an execution *consumed* rides the receipt as a report and prices nothing.
- **Abort classes in the outcome vector.** Fee attribution rides the certificate itself ([04-execution-semantics.md](04-execution-semantics.md) §4), so settlement needs no side channel.

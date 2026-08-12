# Host integration: the contract between engine and protocol

The engine is embedded by a sharded BFT host that commits transactions before executing them, transfers state between shards as merkle-proven provisions, and finalizes cross-shard transactions by unanimous execution certificates. This document states what the engine's design requires of that host and what it hands back — the boundary at which the `INV-VM-*` register meets the host's own invariant families (documented in the hyperscale-rs repository's `docs/`).

## 1. Provisions carry the read set and nothing else

A provision bundle needs to carry only what a counterpart must *read*: fresh-read values and the prior values of read-modify-write keys ([01-effects-and-routing.md](01-effects-and-routing.md) §3). A `delta` reads nothing; a `reserve`'s feasibility is judged at the owning shard; a blind `write` needs no prior value. Legs composed of commutative effects provision nothing and dispatch immediately.

An empty bundle is still emitted, because the same wire edge does a second job: it is **engagement evidence**. A counterpart engages a cross-shard transaction only against evidence that the shard paying its fee committed it, and every other participant echoes its own commitment back to the payer the same way (§2).

## 2. Cross-shard fee assurance

Fee payment is a `reserve` on the payer's vault, so the payer's shard is a participant by routing; what needs sequencing rules is that counterpart shards commit independently and would otherwise engage locks and burn work before learning the reservation is feasible — the insolvent-payer griefing vector. Three rules close it:

1. **Reservation at the payer's shard is a block-validity condition.** The signed `max_fee` reservation — the gas ceiling plus declared-footprint pricing, over a fixed charge for carrying the transaction at all — must engage for the payer's shard to commit the transaction at all. The three terms are one quantity, `declared_work`, priced on the same schedule that prices what execution goes on to attest, so a declaration always covers the attestation it can produce and a host can release exactly what it reserved. The fixed term is what makes a budget over that quantity bound how *many* transactions are in flight and not only how heavy they are: both other terms go to nearly zero for a minimal declaration signing a zero ceiling, while the per-transaction cost of tracking it does not. Feasibility is deterministic (committed balance minus prior reservations, hash-ordered), so payer insolvency after commitment is impossible by reservation semantics.
2. **Commit-proof-gated engagement.** A non-payer participant admits the transaction to a proposal — engaging locks, starting its deadline clock — only against a commit proof of the payer shard's block containing it, checked at vote as a validity rule so a Byzantine proposer cannot grief its own shard with unpayable transactions (INV-VM-9). The payer's shard commits first and the finalization deadline anchors on its commit. A certified-but-uncommitted payer block engages nothing.
3. **Fees never move cross-shard: burn locally, compensate by attested work.** On finalization the attested actual burns at the payer's shard and the surplus releases; on abort the class floor burns and the rest releases — both written inside the settling receipt (INV-VM-10). Non-payer participants are compensated the way storage is: per-shard work aggregates from finalized ticks cross into the host's fold through the same witness channel as the attested stored-byte totals that compensate storage ([03-objects-and-state.md](03-objects-and-state.md) §3), and the fold reweights the fixed per-epoch emission by both. No fee transfer, no netting protocol. Work pays validators; burns discipline users; emission-farming by self-dealing traffic spends real burned fees, so the burn-to-emission ratio is the sybil defense.

A reservation is an accounting entry over the payer shard's own committed chain, never an on-chain hold — release is the entry ceasing to be derivable, and under payer-shard termination there is nothing to inherit and nothing to sweep ([03-objects-and-state.md](03-objects-and-state.md) §7). A composed subintent transaction has exactly one fee payer, the composer, because per-subintent payers would create circular commit-proof dependencies among multiple first-committing shards; subintents reimburse the composer in-band. A reservation may be **contingent above the floor**: the abort-class floor always settles, but the remainder charges only on success — the natural shape for a composer underwriting others' intents.

**The payer's vote is echo-gated.** The payer shard's committee votes once per cross-shard transaction, on a condition that is a pure function of its own chain: the success vote exists only with every counterpart's engagement echo committed on the payer's chain; past the transaction's validity window without full echo coverage, the committee's single statement is the all-abort vote carrying the fee record (INV-VM-11). The payer never resolves a transaction on a local timer after speaking, so no verdict splits.

Griefing residual, on record: the payer's shard can commit and reserve while a counterpart never commits; the deadline abort's floor fee must cover a full participant's wasted cycle.

**Rejected: exchange-rate-pegged pricing.** A ledger-state exchange rate is an exogenous oracle input into consensus pricing; every other quantity in this economics is endogenous and fold-derived. Token-denominated prices are governance-adjustable if they drift.

## 3. Authority: presence at admission, satisfaction at execution

A manifest node calling a guarded method presents evidence, and every badge it presents is produced inside its own intent: the composer's signature for a root-intent node, the declared signer's for a subintent node (INV-VM-12). A method's accessibility is package metadata, content-addressed with the code it describes and judged at publish, so no transaction can weaken it and no shard reads it differently. Presence is a pure function of signed content, with no state read, and is reached at admission ahead of ordering and fee exposure: an envelope that presents nothing where something is required never enters a block and nobody pays for it.

Whether what a call presents *satisfies* its target is a separate question with a separate answer (INV-VM-15). A method requires an identity its own target names — its own address, or a slot of its creation-fixed configuration — so the verdict is reached at execution, against the target, and never by reading state under a prefix the manifest did not name. An account with no auth module of its own is governed by the identity its address derives, so today the two halves coincide for a virtual account and the composer's own badge satisfies its own account directly. A call presenting anything else aborts and its sender pays the ceiling they signed: both what the call presents and what the target requires are content the signer put their name to.

## 4. What the host provides the environment

- **The transaction clock**: the canonical weighted-time anchor of the payer-shard block that committed the transaction, carried by the same commit proof §2 requires — one value per transaction, identical on every participant ([04-execution-semantics.md](04-execution-semantics.md) §3).
- **Randomness**: the payer block's attested randomness, domain-separated, drawn per transaction hash.
- **Nothing else.** No shard-local time, no schedule position, no per-execution entropy (INV-VM-14).

## 5. What the engine hands back

- **Shard-invariant outputs.** Execution projects to a form every participant derives identically — receipt hash, events, outcome — with only the database writes filtered per shard by ownership. All failures collapse to one canonical failed-receipt hash.
- **Events as consensus content.** Blueprint-declared, WIT-typed, size- and count-capped, carried success-only, homed on the emitting object's shard — a multi-shard transaction's events ride only their emitters' receipts — and merkled into the receipt root. The host's beacon witness channel consumes the staking component's events from its home shard.
- **Attested work.** Each finalized tick's receipts carry the work the shard actually executed — compute plus declared footprint, locality-scoped — which is what the emission reweighting in §2 consumes.
- **Abort classes in the outcome vector.** Fee attribution rides the certificate itself ([04-execution-semantics.md](04-execution-semantics.md) §4), so settlement needs no side channel.

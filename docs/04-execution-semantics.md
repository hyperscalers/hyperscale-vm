# Execution semantics: deterministic parallelism, the clock, aborts, and fees

## 1. Conflict groups and canonical order

With verified effect sets, parallelism needs no speculation. The kernel's batch executor (`crates/kernel`) sorts a committed batch into canonical transaction-hash order, judges reservations, partitions the batch into conflict groups by the mode compatibility relation ([01-effects-and-routing.md](01-effects-and-routing.md) §2), executes groups in parallel, and applies effects in canonical order. The schedule is a pure function of committed content — every replica derives the same groups — so this is not optimistic concurrency and requires no reconciliation.

- Commutative modes widen the groups: a thousand deposits to one vault are one parallel group with a canonical delta fold, not a serial chain.
- A conflict group is a sequential chain against one overlay, so members see each other's writes: a group is the mechanism that makes committing a conflicting set safe rather than a hazard. Fifty withdrawals against a well-funded vault all succeed; only genuine overdrafts abort, at the floor.
- The dispatch seam is the host's thread pool; determinism lives in the schedule derivation, not the thread timing. Receipts are byte-identical across serial, parallel, and adversarially permuted worker schedules (INV-VM-14), and the harness pins that continuously as a metamorphic test.

## 2. No execution-position observability

The schedule's soundness rests on one closure property: the only order-sensitive channels are declared effects, which the compatibility relation forces into conflicts that canonical order then resolves identically everywhere. The environment therefore never leaks schedule position — no intra-block index, no "transactions before me," no per-execution entropy beyond the transaction-hash-derived draw. Every environment addition is checked against this rule first. ID generation already respects it: fresh object IDs hash the signed envelope and the call site's position, with no allocation counter, so uniqueness needs no coordination and no sequencing.

## 3. The transaction clock and randomness

Replicated execution forces a single clock value per transaction: every participant computes the same receipt, so a component can never read "its own shard's" time. The clock is **the canonical weighted-time anchor of the payer-shard block that committed the transaction** — available at exactly the right moment on both sides: locally the anchor exists at the instant of commit, and remotely it rides the commit proof every non-payer participant already requires before engaging ([08-host-integration.md](08-host-integration.md) §2). Single-shard transactions degenerate cleanly, and application-visible time is coherent with the finalization deadline, which anchors on the same instant.

The monotonicity contract is explicit: exact along one payer chain, approximate globally — successive transactions at one component may carry clocks from different payer chains, with regression bounded by the Byzantine skew envelope plus commit lag. Stdlib time arithmetic saturates ([07-stdlib-and-upgrades.md](07-stdlib-and-upgrades.md)), so applications never see negative elapsed time.

Randomness is the same shape: the payer block's attested randomness, domain-separated per transaction with the draw keyed on the transaction hash — per-transaction committed content, identical on every participant, revealing nothing about schedule position.

## 4. Abort taxonomy

Aborts are load-bearing in a deterministic cross-shard protocol — deadline all-aborts, race tiebreaks, reshape fences — and static access deliberately adds a retry class (stale declarations). Induced aborts must therefore never be free. Classes, mapped one-to-one onto the execution certificate's outcome vector so fee attribution is itself attested:

| Class | Meaning | Fee |
|---|---|---|
| **User error** | Gate trap (undeclared access), auth failure, guest panic, fuel exhaustion | Full freight: the declared gas limit and every other quantity in full, all shards — settled from declarations, never from trap-time fuel, which is engine-defined |
| **Infeasibility** | Lost a deterministic race: reservation infeasible, debit or settle past the floor an earlier transaction in the group left, a write's presence requirement the committed leaf no longer meets, stale declaration | Floor fee covering consumed scheduling and provisioning work |
| **Protocol** | Finalization deadline, reshape fence, recovery fence — no counterparty at fault | Floor fee; never punitive, the sender did nothing wrong |

Griefing accounting: a transaction engineered to abort still held locks and burned remote work; user-error pricing makes that a paid attack with linear cost.

Where a class is ambiguous between defect and race, it is priced as the race. A sender who declared `create` on a leaf that already existed and one whom somebody beat to it leave identical state, so the protocol cannot separate them; charging the ceiling would bill every honest loser to reach the careless caller, and would turn any leaf a third party can create into a lever for spending somebody else's declared maximum. The same reading puts a presented authority a target no longer admits in this row rather than the one above.

**A decline is not an abort.** A method may carry a refusal channel and return through it — the guest ran to completion and said no on its own terms, which is a different event from any row above and is priced as one: the transaction does not commit, but the invocation is charged the fuel it actually spent rather than the ceiling a trap is charged, because an export that returned reaches an ordinary completed figure both engines derive by construction. What comes back is an index into the package's own table of refusals, so a receipt records which refusal rather than a string an author chose. Whether a method has the channel at all is a fact about its compiled type that the publish gate holds it to ([01-effects-and-routing.md](01-effects-and-routing.md) §9) — the converse mark, that a method cannot decline *or* trap, is what lets a caller commit against it without waiting.

## 5. The fee quantities

Five priced quantities, all deterministic:

1. **Compute** — engine fuel, including canonical-ABI boundary copies ([05-runtime.md](05-runtime.md) §2), split in two: a non-refundable **pipeline occupancy** charge on the declared gas limit — block space and commit-to-execute backlog are consumed by the declaration whether or not the gas burns — and a refundable **execution** charge settled on the certificate-attested actual. Over-declaration costs linearly in the slack; there is no refund cliff to game, and honest variance pays only the cheaper occupancy rate.
2. **State** — the storage bond at creation plus its non-refundable churn fraction ([03-objects-and-state.md](03-objects-and-state.md) §3); a deposit creating deferred-bond state pays the unbonded premium instead.
3. **Declaration footprint** — declared keys and modes, priced per shard touched, per exclusivity class, and — for range targets — per order-of-magnitude of the declared interval. Looseness and hot exclusive access are metered, which pushes toward tight declarations, commutative modes, and argument lifting without any protocol mandate. Two shape facts are load-bearing. First, **the exclusivity ordering is the lattice's, and `read` is not where intuition puts it**: counted off the compatibility relation, `write` excludes four kinds, `read` three, `delta` and `reserve` two each, `locked` none. A fresh read is *more* disruptive than a delta — two deltas on one amount cell coexist, and a single fresh read on that cell conflicts with both — so pricing reads below reservations would make the cheapest declaration on a hot cell the one that serializes the most traffic across it. The weights derive from the relation rather than being tabulated beside it, so the two cannot drift. Second, **range width is priced and the range cap is not**: an interval spanning a whole collection excludes every other declaration on it, so width is charged in orders of magnitude claimed — what occupies an interval is state a signing-time price may not read — while the cap needs no term of its own, since it bounds entries touched and each entry already pays the boundary-copy charge. The computed quantity lives in `crates/effects` as the footprint; the unit prices are economics calibration.
4. **Lock occupancy** — hold time on contended keys, registered so griefing analysis prices intentional hold-stretching.
5. **Retention bytes** — transaction payload, events, logs, and receipt content: bytes every node stores and gossips under DA retention yet that are not state the bond covers. Priced per byte, non-refundable — nothing here is deletable, so there is no refund to shape. Unpriced receipt bytes would be a cheap amplification attack on exactly the retention budget the storage bond defends.

## 6. Static gas bounds

Block budgeting runs on declared limits because determinism gives replay exactness and certificate-attested actuals, never proposal-time exactness: static access fixes which keys are touched, not value-dependent control flow, and a cross-shard transaction cannot be pre-executed at proposal — its provisions do not exist yet. Where cost *is* decidable, it is verified rather than declared: a method whose control flow is independent of **state values** carries a deploy-verified static gas bound in its effect metadata. Environment inputs — the transaction clock, attested randomness — count as exact-class inputs, so vesting-style time arithmetic stays in the exact tier. For that class the declared limit is the computed bound: no estimation, no slack, no griefing surface. The pipeline-occupancy price disciplines only the residual value-dependent class.

## 7. MEV posture

Static declarations make intent legible in the mempool — a visible effect set is a sandwich invitation. The posture is locked, not a shipped mechanism: the **effect set stays plaintext** (scheduling, routing, and locking need it), and the design must **not foreclose** threshold-encrypting the payload — amounts, bounds — until ordering commits. The transaction format keeps the manifest and the effect set separable, and nothing in admission requires payload plaintext before the block seals.

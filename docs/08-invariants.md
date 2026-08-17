# Invariant register

The consolidated register of the VM's safety and determinism properties, with stable IDs. Each entry names the property, classifies it, states it precisely enough to be a verification target, and points to the document section that motivates it. IDs are never reused or renumbered.

This register owns the `INV-VM-*` family. The host protocol's families — `INV-SHARD-*`, `INV-EXEC-*`, `INV-BEACON-*`, and the rest — live in the hyperscale-rs repository's `docs/08-invariants.md`, which cites entries here where its narratives touch the VM. Host-boundary entries (INV-VM-9 through 12) state requirements the engine's design places on any host; their enforcement lives in host code, their content is fixed here.

**Classification.** *Safety* — never violated in any reachable state, regardless of timing. *Determinism* — a functional property (same inputs ⇒ same outputs across replicas) that safety properties reduce to.

---

## Effect model — [01](01-effects-and-routing.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-1** | Safety | **Access truth.** No execution reads or writes any substate outside the transaction's evaluated effect set; violation is inexpressible in the runtime (no handle exists for an undeclared key), and any attempted violation aborts identically on every replica. Enforcement is by capability construction, so nothing about safety depends on declarations being right — the compiler owes tightness, the gate owes soundness. What bounds the set itself is INV-VM-16: this says execution stays inside what was declared, and says nothing about what a declaration may claim. |
| **INV-VM-2** | Determinism | **Routing purity.** `route` is a pure function of the signed transaction and content-addressed package metadata; every honest node derives identical routing, key sets, and modes for any transaction it can encounter. |
| **INV-VM-3** | Determinism | **Locked reads.** A `locked` read resolves against a substate no version of which differs, so its value is identical on every replica and never depends on local timing; a `locked` effect declared on an unlocked target aborts identically everywhere. |
| **INV-VM-16** | Safety | **Declaration ownership.** Every effect a frame's clauses evaluate to carries that frame's own instance as the owner half of its key. An argument, a configuration slot, a `for-each` binding and a literal all name another object's prefix and are refused — at publish on the target expression, so an author hears about it, and again at routing on the evaluated effect, where no expression shape can be overlooked. An object's cells are therefore reachable by calling it and never by naming them, which is what makes a method's accessibility the only way in. Kernel effects are not frame declarations: the nullifier a bound subintent spends sits under its signer's prefix, no signature declared it, and it reaches the routing view directly. |

## Manifest — [02](02-manifests-and-intents.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-8** | Determinism | **Order-free meaning.** A manifest's meaning is a function of its dataflow graph, never of any encoding order: well-formedness (single producer and consumer per edge, acyclicity, type agreement with the target metadata) is checked at admission, and effect derivation over a well-formed manifest is order-independent — every node evaluates the identical effect set from the identical bound inputs on every replica. |

## Objects and state — [03](03-objects-and-state.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-4** | Safety | **Structural ownership.** An object's owner is fixed at creation and changes only by explicit kernel move; the storage key's owner half always equals the kernel's ownership record. No resolution walk exists. |
| **INV-VM-5** | Determinism | **Reshape-clean accumulators.** Every stdlib accumulator's value under split/merge composition equals its value had the reshape not occurred; reshape neither creates, loses, nor double-counts any accumulated quantity. |
| **INV-VM-6** | Safety | **Conservation.** For every resource, the sum of per-shard supply accumulators plus in-flight attested cross-shard movements equals minted-minus-burned supply at all times; no execution path changes a shard's accumulator except mint, burn, or an attested cross-shard movement. |
| **INV-VM-7** | Safety | **Bond conservation.** Every substate carries either a paid bond or a recorded debt at the rate in force at its creation; bond and debt totals change only by creation, debt settlement, deletion refund, and reshape composition — which conserves them — and an indebted account never exceeds its substate cap. |
| **INV-VM-17** | Safety | **Value linearity.** Value in flight exists only as a handle the kernel produced, and every producer is the kernel's own — an edge routed to a call, a debit against a declared cell, an issue a declaration granted — so a guest has no way to bring one into being. Between production and settlement it is neither duplicated nor lost: a committing transaction leaves no value held, and a body that lets go of value is refused at the boundary. The property is the kernel's alone, held without trusting either engine's canonical ABI to be right about which handle is which. Where INV-VM-6 conserves supply across shards, this conserves it inside one transaction. |

## Execution — [04](04-execution-semantics.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-14** | Determinism | **Schedule invariance.** A committed batch's receipts are a pure function of committed content: byte-identical across serial, parallel, and adversarially permuted execution schedules. No environment input reveals schedule position — no intra-block index, no per-execution entropy beyond the transaction-hash-derived draw — and the clock and randomness are per-transaction committed content, identical on every participant. |

## Encoding — [05 §5](05-runtime.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-13** | Determinism | **Canonical at decode.** Every hashed, signed, or persisted value has exactly one valid byte encoding; the decoder rejects any other bytes — unsorted maps, non-minimal integers, trailing bytes — so value equality and byte equality coincide, as decoder construction rather than encoder discipline. |

## Host boundary — [07](07-host-integration.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-9** | Safety | **Commit-proof-gated engagement.** A non-payer shard engages a cross-shard transaction — admits it to a proposal, takes its locks, starts its deadline clock — only while holding a transaction commit proof: the payer shard's provisions bundle naming the transaction (empty entries for a commutative leg), consumable only against a commit-proven header of the payer block that committed it under its `max_fee` reservation. A certified-but-uncommitted payer block engages nothing; an insolvent payer's transaction never commits at the payer shard (the reservation is a block-validity condition) and so engages no counterpart lock anywhere. |
| **INV-VM-10** | Safety | **Reservation resolution.** Every fee reservation a payer-shard block engages resolves exactly once, and fees never move cross-shard: a transaction that finalizes burns at the payer shard — the attested actual on success, the class floor on abort — inside the receipt its own settlement writes, and releases the remainder. A reservation is an accounting entry over the payer shard's own committed chain, never an on-chain hold, so release is that entry ceasing to be derivable; under payer-shard termination there is nothing to inherit and nothing to sweep. Payer balance plus held reservations plus cumulative burn is conserved throughout. |
| **INV-VM-11** | Safety | **Echo-gated payer vote.** The payer shard's committee votes once per cross-shard transaction, on a condition that is a pure function of its own chain: the success vote exists only with every counterpart participant's engagement echo — the (possibly empty) bundle the counterpart's committing block owes the payer — committed on the payer's chain; past the transaction's validity window without full echo coverage, the committee's single statement is the all-abort vote carrying the fee record. The payer never resolves a transaction on a local timer after speaking: a counterpart's late in-window success certificate loses worst-wins to the abort vote consistently on every participant, so no verdict splits. |
| **INV-VM-12** | Safety | **Evidence presence.** A manifest node calling a guarded method presents evidence, and every badge it presents is produced inside its own intent: the composer's signature for a root-intent node, the declared signer's for a subintent node. Accessibility is package metadata, content-addressed with the code it describes and judged at publish, so no transaction can weaken it and no shard reads it differently; the verdict is a pure function of signed content, reached at admission, so a malformed envelope never enters a block and nobody pays for it. Authority does not propagate through a call: a frame reached from a static call site holds no badge, so a guarded method is unreachable from one. |
| **INV-VM-15** | Safety | **Rule satisfaction.** A guarded call completes only if the evidence it presents carries the identity its target requires, and that identity is one the target itself names — its own address, or a slot of its creation-fixed configuration. The verdict is reached at execution, against the target, so no authority question is answered by reading state under a prefix the manifest did not name; a call presenting anything else aborts identically on every replica and its sender pays the ceiling they signed. |

---

## Notes for the verification effort

- **The core** ([00-overview.md](00-overview.md)): access truth (INV-VM-1/2), conservation (INV-VM-5/6/7/17), fee assurance (INV-VM-9/10/11), schedule invariance (INV-VM-14). Everything else supports these or bounds resources.
- **Reduction structure.** The host's atomic-commitment argument consumes this register wholesale: deterministic execution (INV-VM-1/13/14) is what lets certificates attest rather than choose outcomes, and the host's own registers state that dependency from their side.
- **Existing mechanized anchors.** The trace-subset oracle (asserts INV-VM-1 continuously, on every scenario, differential, and fuzz workload), the metamorphic schedule-permutation tests (INV-VM-14), the canonical-decode mutation proptests (INV-VM-13), and the differential lanes between the blessed engine and `crates/ref` are the executable counterparts to cross-validate models against. The fee-assurance model in the host repository's `specs/vm_fee_assurance.qnt` covers INV-VM-9/10/11 and records where it is stricter than the code.

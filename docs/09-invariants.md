# Invariant register

The consolidated register of the VM's safety and determinism properties, with stable IDs. Each entry names the property, classifies it, states it precisely enough to be a verification target, and points to the document section that motivates it. IDs are never reused or renumbered.

This register owns the `INV-VM-*` family. The host protocol's families — `INV-SHARD-*`, `INV-EXEC-*`, `INV-BEACON-*`, and the rest — live in the hyperscale-rs repository's `docs/08-invariants.md`, which cites entries here where its narratives touch the VM. Host-boundary entries (INV-VM-9 through 11) state requirements the engine's design places on any host; their enforcement lives in host code, their content is fixed here.

**Classification.** *Safety* — never violated in any reachable state, regardless of timing. *Determinism* — a functional property (same inputs ⇒ same outputs across replicas) that safety properties reduce to.

---

## Effect model — [01](01-effects-and-routing.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-1** | Safety | **Access truth.** No execution reads or writes any substate outside the transaction's evaluated effect set; violation is inexpressible in the runtime (no handle exists for an undeclared key), and any attempted violation aborts identically on every replica. Enforcement is by capability construction, so nothing about safety depends on declarations being right — the compiler owes tightness, the gate owes soundness. What bounds the set itself is INV-VM-16: this says execution stays inside what was declared, and says nothing about what a declaration may claim. A guarded clause is inside it rather than an exception to it: a clause whose guard does not hold declares no effect, so no capability is materialized, and the parameter its handle would have occupied is seated at a reserved rep the table never assigns. Reaching one is a body whose control flow disagrees with the verdict it was handed, and it aborts by that name on every replica. A guard is a fact about the cell rather than about the line that named it — one cell is one clause and one condition, and what it carries is the condition holding at every place the body reaches that cell — so a cell reached from more than one place is declared unconditionally and its handle is there on every path. The rule fails only towards declaring more. |
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
| **INV-VM-5** | Determinism | **Reshape-clean supply accumulators.** The per-shard supply ledger's value under split/merge composition equals its value had the reshape not occurred; composing two children's ledgers yields exactly the parent's, so reshape neither creates, loses, nor double-counts any accumulated supply. The ledger is the one accumulator with a compose law; a future stdlib accumulator joins this entry by defining and testing its own. |
| **INV-VM-6** | Safety | **Conservation.** What the engine holds: every receipt carries the supply deltas its execution caused — mint, burn, and the cross-shard movements its settlement attests — and nothing else moves them; an aborted transaction's deltas are zero; folding a batch's receipts into a shard's accumulator is associative and order-free. The global statement — per-shard accumulators plus in-flight attested movements sum to minted-minus-burned at all times — is the host's to close: the host folds `receipt.supply` into a persisted per-shard ledger at its commit path and judges movements against it, which is wiring that does not yet exist. |
| **INV-VM-7** | Safety | **Bond conservation** — *designed, not implemented.* The design: every substate carries either a paid bond or a recorded debt at the rate in force at its creation; bond and debt totals change only by creation, debt settlement, deletion refund, and reshape composition — which conserves them — and an indebted account never exceeds its substate cap. No bond, rent, debt, or refund machinery exists in either workspace today; the entry stands as the verification target the bond economy must meet when it is built ([03 §3](03-objects-and-state.md)). |
| **INV-VM-18** | Safety | **Value at rest.** A cell holding value names the resource it holds, and that name is the material its key is derived from — so one leaf holds one resource by construction, and a cell filled under one name is not one a withdrawal under another reaches. What the declaration says chooses the capability: a cell that names a resource is reached only through a handle that credits and debits it, one that says nothing only through a handle that reads and replaces bytes, and the two share no operation — so a balance is moved and never written, and a value cell has no byte surface a body can reach. One cell is one answer, held at publish against the target expressions and again at materialization against the evaluated keys, so no leaf is handed out as both. Where INV-VM-17 conserves value in flight, this conserves the cells it rests in: without it a body could assign itself a balance and debit it through the ordinary movement, producing an edge INV-VM-17 would find well-formed. |
| **INV-VM-17** | Safety | **Value linearity.** Value in flight exists only as a handle the kernel produced, and every producer is the kernel's own — an edge routed to a call, a debit against a declared cell, an issue a declaration granted — so a guest has no way to bring one into being. Between production and settlement it is neither duplicated nor lost: a committing transaction leaves no value held, and a body that lets go of value is refused at the boundary. The property is the kernel's alone, held without trusting either engine's canonical ABI to be right about which handle is which. Where INV-VM-6 conserves supply across shards, this conserves it inside one transaction. |

## Execution — [04](04-execution-semantics.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-14** | Determinism | **Schedule invariance.** A committed batch's receipts are a pure function of committed content: byte-identical across serial, parallel, and adversarially permuted execution schedules. No environment input reveals schedule position — no intra-block index, no per-execution entropy at all, since a draw is a function of a commitment the package made in an earlier transaction. The kernel takes the clock, the epoch and the seed window opaquely per transaction; that all three are committed content, identical on every participant, is the host's obligation, on the same terms as INV-VM-9 through 11. |

## Encoding — [05 §5](05-runtime.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-13** | Determinism | **Canonical at decode.** Every hashed, signed, or persisted value has exactly one valid byte encoding; the decoder rejects any other bytes — unsorted maps, non-minimal integers, trailing bytes — so value equality and byte equality coincide, as decoder construction rather than encoder discipline. |

## Authority — [06](06-authority.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-12** | Safety | **Evidence presence.** A manifest node calling a guarded method presents evidence, and every badge it presents is produced inside its own intent: the composer's signature for a root-intent node, the declared signer's for a subintent node. Accessibility is package metadata, content-addressed with the code it describes and judged at publish, so no transaction can weaken it and no shard reads it differently; the verdict is a pure function of signed content, reached at admission, so a malformed envelope never enters a block and nobody pays for it. A method a package could name on its own would hold no badge, which is why a package names none: every invocation is a node the signer wrote down, carrying the evidence that node presents. |
| **INV-VM-15** | Safety | **Rule satisfaction.** A guarded call completes only if the evidence it presents carries the identity its target requires, and that identity is one the target itself names — its own address, or a slot of its creation-fixed configuration. The verdict is reached at execution, against the target, so no authority question is answered by reading state under a prefix the manifest did not name; a call presenting anything else aborts identically on every replica and its sender pays the ceiling they signed. |

## Publish gate — [01 §6](01-effects-and-routing.md), [07](07-stdlib-and-upgrades.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-19** | Safety | **Mark honesty.** A method's totality mark is a function of its artifact: a signature is `Fallible` exactly where its export carries the declared error arm, and `Total` only from protocol provenance and only where the artifact's own scan supports the claim — a published package cannot claim the mark at all. A wrong mark is not a lost optimisation but a torn settlement: an outbound leg the core already committed against, failing. |
| **INV-VM-20** | Safety | **Declared production.** A signature's declared value outputs equal the edges its export hands back, so a package cannot describe itself as producing value its code does not hand over, or hand over value its signature never declared. |

**Enforcement map.** The gate's verdict is one pure function of the bytes, reached wherever the bytes are; what the table records is which rule is deliberately judged at more than one door and which has exactly one.

| Gate rule | Invariant | Enforcement sites |
|---|---|---|
| Deterministic profile (`validate_component`) | INV-VM-13's substrate | Two by design: `cargo hyperscale` at build, the gate at admission — the same call, so a refused artifact is refused before anyone signs one |
| Metadata section present, canonical, within budget | INV-VM-13 | Same two doors, same call |
| Composed signature check (`check_signature`) | INV-VM-16 and the signature bounds | Two by design: the gate, and `MetadataCache::publish` — the cache's own door, so no path seeds a record past the judgment |
| ABI binding vs export type (`check_abi_against_export`) | INV-VM-1's materialization contract | Single point: the gate |
| Declared outputs vs export edges (`check_outputs_against_export`) | INV-VM-20 | Single point: the gate |
| Totality judgment (`judge_totality`) | INV-VM-19 | Single point: the gate; the scan it reads is `check_method`, whose admission terms are the runtime's `DISCHARGED` allowlist |

## Host boundary — [08](08-host-integration.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-9** | Safety | **Commit-proof-gated engagement.** A non-payer shard engages a cross-shard transaction — admits it to a proposal, takes its locks, starts its deadline clock — only while holding a transaction commit proof: the payer shard's provisions bundle naming the transaction (empty entries for a commutative leg), consumable only against a commit-proven header of the payer block that committed it under its `max_fee` reservation. A certified-but-uncommitted payer block engages nothing; an insolvent payer's transaction never commits at the payer shard (the reservation is a block-validity condition) and so engages no counterpart lock anywhere. |
| **INV-VM-10** | Safety | **Reservation resolution.** Every fee reservation a payer-shard block engages resolves exactly once, and fees never move cross-shard: a transaction that finalizes burns at the payer shard — the attested actual on success, the class floor on abort — inside the receipt its own settlement writes, and releases the remainder. A reservation is an accounting entry over the payer shard's own committed chain, never an on-chain hold, so release is that entry ceasing to be derivable; under payer-shard termination there is nothing to inherit and nothing to sweep. Payer balance plus held reservations plus cumulative burn is conserved throughout. |
| **INV-VM-11** | Safety | **Echo-gated payer vote.** The payer shard's committee votes once per cross-shard transaction, on a condition that is a pure function of its own chain: the success vote exists only with every counterpart participant's engagement echo — the (possibly empty) bundle the counterpart's committing block owes the payer — committed on the payer's chain; past the transaction's validity window without full echo coverage, the committee's single statement is the all-abort vote carrying the fee record. The payer never resolves a transaction on a local timer after speaking: a counterpart's late in-window success certificate loses worst-wins to the abort vote consistently on every participant, so no verdict splits. |

---

## Notes for the verification effort

- **The core** ([00-overview.md](00-overview.md)): access truth (INV-VM-1/2), conservation (INV-VM-5/6/7/17), fee assurance (INV-VM-9/10/11), schedule invariance (INV-VM-14). Everything else supports these or bounds resources.
- **Reduction structure.** The host's atomic-commitment argument consumes this register wholesale: deterministic execution (INV-VM-1/13/14) is what lets certificates attest rather than choose outcomes, and the host's own registers state that dependency from their side.
- **Existing mechanized anchors.** The trace-subset oracle (asserts INV-VM-1 continuously, on every scenario, differential, and fuzz workload), the metamorphic schedule-permutation tests (INV-VM-14), the canonical-decode mutation proptests (INV-VM-13), and the differential lanes between the blessed engine and `crates/ref` are the executable counterparts to cross-validate models against. The fee-assurance model in the host repository's `specs/vm_fee_assurance.qnt` covers INV-VM-9/10/11 and records where it is stricter than the code.

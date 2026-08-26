# Invariant register

The consolidated register of the VM's safety and determinism properties, with stable IDs. Each entry names the property, classifies it, and states it precisely enough to be a verification target. The argument for why a property holds — what it defends against, how it relates to its siblings — lives in the narrative document each section names; an entry states the rule and where it is enforced, and nothing twice.

**Namespace.** IDs are `INV-VM-<AREA>-<n>`, one family per section below. The `VM` segment marks the boundary: the host protocol's families — `INV-SHARD-*`, `INV-EXEC-*`, `INV-BEACON-*`, and the rest — live in the hyperscale-rs repository's `docs/08-invariants.md`, which cites entries here where its narratives touch the VM, and a bare `grep INV-VM-` finds every such citation across both repositories. Numbers run within a family and are never reused or renumbered; a property that stops holding is retired in place rather than deleted. Host-boundary entries state requirements the engine's design places on any host; their enforcement lives in host code, their content is fixed here.

**Classification.** *Safety* — never violated in any reachable state, regardless of timing. *Determinism* — a functional property (same inputs ⇒ same outputs across replicas) that safety properties reduce to. There is no liveness class: the engine owns no liveness property, because nothing it does is a wait. Every deadline, every timer, and every progress guarantee touching a VM transaction is the host's, and is stated in the host register.

---

## Access and routing — [01](01-effects-and-routing.md), [02](02-manifests-and-intents.md)

What a transaction can touch. Two halves that do not imply each other: ACCESS-1 says execution stays inside what was declared, ACCESS-4 says what a declaration may claim. Safety needs both — the first alone bounds a frame to a set it wrote itself.

| ID | Class | Property |
|---|---|---|
| **INV-VM-ACCESS-1** | Safety | **Access truth.** No execution reads or writes any substate outside the transaction's evaluated effect set. Enforcement is by capability construction — no handle exists for an undeclared key — so nothing about safety depends on declarations being right: the compiler owes tightness, the gate owes soundness. A clause whose guard does not hold declares no effect and materializes no capability, and the parameter its handle would have occupied is seated at a reserved rep the table never assigns; reaching one is a body whose control flow disagrees with the verdict it was handed, and it aborts by that name on every replica. [01 §2, §6](01-effects-and-routing.md) |
| **INV-VM-ACCESS-2** | Determinism | **Routing purity.** `route` is a pure function of the signed transaction and content-addressed package metadata; every honest node derives identical routing, key sets, and modes for any transaction it can encounter. [01 §7](01-effects-and-routing.md) |
| **INV-VM-ACCESS-3** | Determinism | **Locked reads.** A `locked` read resolves against a substate no version of which differs, so its value is identical on every replica and never depends on local timing; a `locked` effect declared on an unlocked target aborts identically everywhere. [01 §4](01-effects-and-routing.md) |
| **INV-VM-ACCESS-4** | Safety | **Declaration ownership.** Every effect a frame's clauses evaluate to carries that frame's own instance as the owner half of its key; an argument, a configuration slot, a `for-each` binding and a literal all name another object's prefix and are refused — at publish on the target expression, and again at routing on the evaluated effect, where no expression shape can be overlooked. Kernel effects are not frame declarations: the nullifier a bound subintent spends sits under its signer's prefix, no signature declared it, and it reaches the routing view directly. [01 §6](01-effects-and-routing.md) |
| **INV-VM-ACCESS-5** | Determinism | **Order-free meaning.** A manifest's meaning is a function of its dataflow graph, never of any encoding order: well-formedness — single producer and consumer per edge, acyclicity, type agreement with the target metadata — is checked at admission, and effect derivation over a well-formed manifest evaluates the identical effect set from the identical bound inputs on every replica. [02 §1](02-manifests-and-intents.md) |

## Objects and state — [03 §1–5](03-objects-and-state.md)

Cell-level facts: who owns a leaf, what it costs, and what it holds. The quantities that flow through those leaves are the value family below.

| ID | Class | Property |
|---|---|---|
| **INV-VM-OBJ-1** | Safety | **Structural ownership.** An object's owner is fixed at creation and changes only by explicit kernel move; the storage key's owner half always equals the kernel's ownership record. No resolution walk exists. [03 §1](03-objects-and-state.md) |
| **INV-VM-OBJ-2** | Safety | **Bond conservation** — *designed, not implemented.* Every substate carries either a paid bond or a recorded debt at the rate in force at its creation; bond and debt totals change only by creation, debt settlement, deletion refund, and reshape composition — which conserves them — and an indebted account never exceeds its substate cap. No bond, rent, debt, or refund machinery exists in either workspace; the entry stands as the verification target the bond economy must meet when it is built. [03 §3](03-objects-and-state.md) |
| **INV-VM-OBJ-3** | Safety | **Value at rest.** A cell holding value names the resource it holds, and that name is the material its key is derived from, so one leaf holds one resource by construction. What the declaration says chooses the capability: a cell that names a resource is reached only through a handle that credits and debits it, one that says nothing only through a handle that reads and replaces bytes, and the two share no operation. One cell is one answer, held three times — at publish against a signature's target expressions, at publish again per slot across every method a package declares, and at materialization against the evaluated keys. No leaf is handed out as both. [03 §6](03-objects-and-state.md), [01 §2](01-effects-and-routing.md) |

## Value — [03 §6–7](03-objects-and-state.md)

Three scopes of one property: VALUE-3 conserves value inside a transaction, VALUE-2 across the participants of one, VALUE-1 across a reshape. INV-VM-OBJ-3 conserves the cells it rests in, and is what closes the gap a linear edge alone leaves open — without it a body could assign itself a balance and debit it through the ordinary movement, producing an edge VALUE-3 would find well-formed.

| ID | Class | Property |
|---|---|---|
| **INV-VM-VALUE-1** | Determinism | **Reshape-clean accumulators.** The per-shard supply ledger's value under split/merge composition equals its value had the reshape not occurred; composing two children's ledgers yields exactly the parent's, so reshape neither creates, loses, nor double-counts any accumulated supply. It is the one accumulator with a compose law; a future stdlib accumulator joins this entry by defining and testing its own. [03 §5](03-objects-and-state.md) |
| **INV-VM-VALUE-2** | Safety | **Conservation.** For every transaction and every resource, what its value holdings gained equals what they lost, once a mint counts as a loss and a burn as a gain — an amount cell's movements and an instance's presence alike. Checked where the whole transaction is visible and before anything is promoted, so every participant of a cross-shard transaction reaches the same verdict off the same receipt; a transaction that fails it aborts alone, charges nobody, and leaves its batch running. The global statement — per-shard totals plus in-flight movements sum to minted-minus-burned — is a consequence of the history rather than a quantity anything keeps. [03 §6](03-objects-and-state.md) |
| **INV-VM-VALUE-3** | Safety | **Value linearity.** Value in flight exists only as a handle the kernel produced, and every producer is the kernel's own — an edge routed to a call, a debit against a declared cell, an issue a declaration granted — so a guest has no way to bring one into being. Between production and settlement it is neither duplicated nor lost: a committing transaction leaves no value held, and a body that lets go of value is refused at the boundary. The property is the kernel's alone, held without trusting either engine's canonical ABI to be right about which handle is which. [03 §6](03-objects-and-state.md) |

## Runtime — [04](04-execution-semantics.md), [05 §5](05-runtime.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-RUN-1** | Determinism | **Schedule invariance.** A committed batch's receipts are a pure function of committed content: byte-identical across serial, parallel, and adversarially permuted execution schedules. No environment input reveals schedule position — no intra-block index, no per-execution entropy at all, since a draw is a function of a commitment the kernel stamped in an earlier transaction. That the clock, the epoch and the seed window the kernel takes opaquely per transaction are committed content identical on every participant — the window resolved from the snapshot governing the block rather than from a node's own fold frontier — is the host's obligation, on the same terms as the host-boundary family. [04 §2–3](04-execution-semantics.md) |
| **INV-VM-RUN-2** | Determinism | **Canonical at decode.** Every hashed, signed, or persisted value has exactly one valid byte encoding; the decoder rejects any other bytes — unsorted maps, non-minimal integers, trailing bytes — so value equality and byte equality coincide, as decoder construction rather than encoder discipline. [05 §5](05-runtime.md) |

## Authority — [06](06-authority.md)

Two verdicts in two places: AUTH-1 is answered at admission over signed content, AUTH-2 at execution against the target. AUTH-3 and AUTH-4 are the other axis — not what a *method* requires of its caller, but what a *resource* requires of everyone who moves it.

| ID | Class | Property |
|---|---|---|
| **INV-VM-AUTH-1** | Safety | **Evidence presence.** A manifest node calling a method that requires evidence presents evidence, and every claim it presents is produced inside its own intent: the composer's signature for a root-intent node, the declared signer's for a subintent node. What a method requires is package metadata, content-addressed with the code it describes and judged at publish, so no transaction can weaken it and no shard reads it differently. The verdict is a pure function of signed content, reached at admission, so a malformed envelope never enters a block and nobody pays for it. [06 §5](06-authority.md) |
| **INV-VM-AUTH-2** | Safety | **Rule satisfaction.** A gated call completes only if the claims it presents satisfy the rule its target names, and every claim that rule can require is one the target itself names — its own address, a slot of its creation-fixed configuration, or the rule stored at a cell the same method declares. The verdict is reached at execution, against the target, so no authority question is answered by reading state under a prefix the manifest did not name; a call presenting anything else aborts identically on every replica and its sender pays the ceiling they signed. A rule the judge it reached cannot answer is refused rather than treated as satisfied. [06 §5](06-authority.md) |
| **INV-VM-AUTH-3** | Safety | **Entries bind every movement.** What may be done with a resource is the answer of the entries its issuer sealed into it, and those entries are folded into the resource's address — so a resource granting differently is a different resource, and immutability is the derivation rather than a promise. Absence withholds: a resource granting no entry for a behaviour is one nobody may perform it on, which is every resource until its issuer says otherwise. The requirement is injected at admission from the resource's own record, through one door for all six behaviours, so no package can omit a gate on value it moves and no two sites can inject different requirements for one entry. [06 §4](06-authority.md) |
| **INV-VM-AUTH-4** | Safety | **A withheld record is refused, never assumed.** A resource whose sealed entries restrict a movement anyone could otherwise make carries the `Restricted` address class. A movement of such a resource presented without its record is refused for the record being withheld, rather than judged as though the resource granted nothing — so a reader holding only an address always knows whether it must have the rules in hand before letting a movement through. [06 §4](06-authority.md) |

## Publish gate — [01 §6, §9](01-effects-and-routing.md), [07](07-stdlib-and-upgrades.md)

| ID | Class | Property |
|---|---|---|
| **INV-VM-GATE-1** | Safety | **Mark honesty.** A method's totality mark is a function of its artifact: a signature is `Fallible` exactly where its export carries the declared error arm, and `Total` only from protocol provenance and only where the artifact's own scan supports the claim — a published package cannot claim the mark at all. A wrong mark is not a lost optimisation but a torn settlement: an outbound leg the core already committed against, failing. [01 §9](01-effects-and-routing.md) |
| **INV-VM-GATE-2** | Safety | **Declared production.** A signature's declared value outputs equal the edges its export hands back, so a package cannot describe itself as producing value its code does not hand over, or hand over value its signature never declared. [01 §9](01-effects-and-routing.md) |

**Enforcement map.** The gate's verdict is one pure function of the bytes, reached wherever the bytes are; what the table records is which rule is deliberately judged at more than one door and which has exactly one.

| Gate rule | Invariant | Enforcement sites |
|---|---|---|
| Deterministic profile (`validate_component`) | INV-VM-RUN-2's substrate | Two by design: `cargo hyperscale` at build, the gate at admission — the same call, so a refused artifact is refused before anyone signs one |
| Metadata section present, canonical, within budget | INV-VM-RUN-2 | Same two doors, same call |
| Composed signature check (`check_signature`) | INV-VM-ACCESS-4 and the signature bounds | Two by design: the gate, and `MetadataCache::publish` — the cache's own door, so no path seeds a record past the judgment |
| ABI binding vs export type (`check_abi_against_export`) | INV-VM-ACCESS-1's materialization contract | Single point: the gate |
| Declared outputs vs export edges (`check_outputs_against_export`) | INV-VM-GATE-2 | Single point: the gate |
| Totality judgment (`judge_totality`) | INV-VM-GATE-1 | Single point: the gate; the scan it reads is `check_method`, whose admission terms are the runtime's `DISCHARGED` allowlist |

## Host boundary — [08](08-host-integration.md)

Requirements the engine's design places on any host. Their enforcement lives in host code; their content is fixed here.

| ID | Class | Property |
|---|---|---|
| **INV-VM-HOST-1** | Safety | **Commit-proof-gated engagement.** A non-payer shard engages a cross-shard transaction — admits it to a proposal, takes its locks, starts its deadline clock — only while holding a transaction commit proof: the payer shard's provisions bundle naming the transaction (empty entries for a commutative leg), consumable only against a commit-proven header of the payer block that committed it under its `max_fee` reservation. A certified-but-uncommitted payer block engages nothing; an insolvent payer's transaction never commits at the payer shard, so it engages no counterpart lock anywhere. [08 §2](08-host-integration.md) |
| **INV-VM-HOST-2** | Safety | **Reservation resolution.** Every fee reservation a payer-shard block engages resolves exactly once, and fees never move cross-shard: a transaction that finalizes burns at the payer shard — the attested actual on success, the class floor on abort — inside the receipt its own settlement writes, and releases the remainder. A reservation is an accounting entry over the payer shard's own committed chain, never an on-chain hold, so release is that entry ceasing to be derivable and payer-shard termination leaves nothing to inherit. Payer balance plus held reservations plus cumulative burn is conserved throughout. [08 §2](08-host-integration.md) |
| **INV-VM-HOST-3** | Safety | **Echo-gated payer vote.** The payer shard's committee votes once per cross-shard transaction, on a condition that is a pure function of its own chain: the success vote exists only with every counterpart participant's engagement echo — the (possibly empty) bundle the counterpart's committing block owes the payer — committed on the payer's chain; past the transaction's validity window without full echo coverage, the committee's single statement is the all-abort vote carrying the fee record. A counterpart's late in-window success certificate loses worst-wins to the abort vote consistently on every participant, so no verdict splits. [08 §2](08-host-integration.md) |

---

## Retired invariants

None yet. A property that stops holding is struck here with what replaced it, rather than being removed from its family: an ID that once appeared in a commit message, a model, or a host document must always resolve to something.

## Notes for the verification effort

- **The core** ([00-overview.md](00-overview.md)): access truth (ACCESS-1/2), conservation (all of VALUE, plus OBJ-2/3), fee assurance (all of HOST), schedule invariance (RUN-1). Everything else supports these or bounds resources.
- **Reduction structure.** The host's atomic-commitment argument consumes this register wholesale: deterministic execution (ACCESS-1, RUN-1/2) is what lets certificates attest rather than choose outcomes, and the host's own registers state that dependency from their side.
- **Existing mechanized anchors.** The trace-subset oracle (asserts ACCESS-1 continuously, on every scenario, differential, and fuzz workload), the metamorphic schedule-permutation tests (RUN-1), the canonical-decode mutation proptests (RUN-2), and the differential lanes between the blessed engine and `crates/ref` are the executable counterparts to cross-validate models against. The fee-assurance model in the host repository's `specs/vm_fee_assurance.qnt` covers the HOST family and records where it is stricter than the code.

## Superseded numbering

The register was renumbered once, from a single flat `INV-VM-<n>` family to the per-area families above. Documents outside these two repositories may still carry the old form.

| Old | New | Old | New |
|---|---|---|---|
| INV-VM-1 | INV-VM-ACCESS-1 | INV-VM-11 | INV-VM-HOST-3 |
| INV-VM-2 | INV-VM-ACCESS-2 | INV-VM-12 | INV-VM-AUTH-1 |
| INV-VM-3 | INV-VM-ACCESS-3 | INV-VM-13 | INV-VM-RUN-2 |
| INV-VM-4 | INV-VM-OBJ-1 | INV-VM-14 | INV-VM-RUN-1 |
| INV-VM-5 | INV-VM-VALUE-1 | INV-VM-15 | INV-VM-AUTH-2 |
| INV-VM-6 | INV-VM-VALUE-2 | INV-VM-16 | INV-VM-ACCESS-4 |
| INV-VM-7 | INV-VM-OBJ-2 | INV-VM-17 | INV-VM-VALUE-3 |
| INV-VM-8 | INV-VM-ACCESS-5 | INV-VM-18 | INV-VM-OBJ-3 |
| INV-VM-9 | INV-VM-HOST-1 | INV-VM-19 | INV-VM-GATE-1 |
| INV-VM-10 | INV-VM-HOST-2 | INV-VM-20 | INV-VM-GATE-2 |

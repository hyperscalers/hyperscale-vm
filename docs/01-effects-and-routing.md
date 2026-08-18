# Effects and routing: static access, modes, and enforcement

Every callable method carries an **effect signature**: a total function from `(component, typed args)` to a set of `(substate key, mode)` pairs. The signature is expressed in a restricted access DSL — field projections, keyed lookups over argument values, canonical-address computation ([03-objects-and-state.md](03-objects-and-state.md)), tuple and list mapping over bounded argument collections, and judgments over those inputs: negation, conjunction, disjunction, equality, ordering of the two integer widths, table membership, and a conditional selecting between two expressions. No loops, no recursion, no arithmetic, no reads of state. Evaluating a signature is O(manifest size) and requires no engine.

Signature inputs are manifest arguments, bound yield parameters ([02-manifests-and-intents.md](02-manifests-and-intents.md) §3), and the target instance's immutable creation-fixed configuration. Argument constraints extend past structural typing: a reference argument can require its target's package and blueprint, checked at admission.

A signature is derived from the method body rather than written beside it (§9). Nothing checks that the derived declaration over-approximates the body, and nothing needs to: a method that under-declares does not get an unchecked access, it gets a handle that was never materialized. A wrong declaration therefore costs its author a trap and costs no one else safety, which is what makes a derived declaration acceptable inside a content-addressed package at all. Residual looseness is a contention and fee cost, never a correctness event. Signatures are fixed at publish and immutable with their package ([07-stdlib-and-upgrades.md](07-stdlib-and-upgrades.md)), so the global metadata cache is content-addressed and never invalidates. A signature answers for its own method and nothing further: a frame may declare only under its own instance's prefix, so state that is not a package's to declare is reached by naming its owner's method in the manifest, as a node of its own.

## 1. Total static access

Access is a pure function of the signed transaction plus immutable metadata. Consequences, each load-bearing:

- **Call targets are manifest-visible.** Every call edge names its target component in the manifest, directly or as an argument. Dynamic dispatch through state-stored addresses does not exist; delegate-style proxies are inexpressible.
- **Level-1 derefs are computation, not state reads.** Canonical child addresses make "the vault for resource R under account A" a computed key. The DSL's keyed lookups never touch state.
- **State-dependent choice is restructured, not supported.** The idioms — argument lifting, commit/claim, pagination cranks, deterministic fresh-object IDs — are stdlib patterns ([07-stdlib-and-upgrades.md](07-stdlib-and-upgrades.md)). The staleness risk of choosing at signing time is the application's, bounded by the enforcement gate: a stale declaration aborts and retries, on the sender's fee.
- **Choice over inputs is expressible; choice over state is not.** A conditional in the DSL reads the call's arguments and the target's configuration, both of which the signed transaction already fixes, so a signature that branches on one is a total function of the same inputs an unconditional signature is. That is what lets a constant-product pool sell either side of one pair from one instance rather than one direction from two. The judgments are strictly typed and their refusals are ordinary evaluation verdicts, identical on every node; a conditional evaluates only the arm it takes, which is what makes a table lookup guarded on membership a default the package chose rather than a routing refusal. There is no arithmetic: ordering compares amounts that already exist and never computes one, because an amount a declaration computed is an amount two nodes could disagree about the rounding of.
- **State verifies; the manifest dispatches.** A component may check what the manifest carries against stored state — an approval hash, a constraint, a quota — and gate a transient authorization edge on the match; it may never *choose* a target or key from state. Every governance-execution pattern walks this line: verification of carried content is ordinary declared reading, dispatch from state is inexpressible.

## 2. The mode lattice

| Mode | Semantics |
|---|---|
| `read` | Fresh coherent read of committed state |
| `locked` | Read of a permanently locked substate — the target cannot change |
| `delta` | Unconditional commutative increment/decrement; the amount is runtime-determined, never declared |
| `reserve(n)` | Conditional decrement, feasible iff committed balance minus prior reservations covers `n` |
| `write` | Exclusive read-modify-write, optionally requiring the leaf absent or present |

Scheduling compatibility (two in-flight transactions touching the same key):

| | `read` | `locked` | `delta` | `reserve` | `write` |
|---|---|---|---|---|---|
| `read` | ✓ | ✓ | ✗ | ✗ | ✗ |
| `locked` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `delta` | ✗ | ✓ | ✓ | ✓ | ✗ |
| `reserve` | ✗ | ✓ | ✓ | ✓ | ✗ |
| `write` | ✗ | ✓ | ✗ | ✗ | ✗ |

**A write says what it requires of the leaf.** `write` carries a *presence* — `either` by default, or `absent` or `present` — and the shard holding the leaf judges it against committed state before the body runs, where it already judges a reservation's feasibility. A requirement the leaf does not meet aborts the transaction with the protocol's own reason rather than a trap the guest wrote, which is what puts a one-way door in the declaration: a caller routes on it, and a wallet can say "this call creates your authority cell, and fails if you already have one" without running anything. Contention is untouched — a create and a write exclude each other exactly as two writes do — so the presence is a feasibility parameter beside `reserve`'s amount, not a mode of its own, and the compatibility table below reads the same whichever it carries.

The requirement is about *the leaf a write lands on*, so it is carried by the two targets that name one — a cell, and a single collection entry — and refused on an interval, which names none and stays valid whatever enters or leaves it. Two clauses on one target meet: `either` concedes to a named requirement, and a requirement against its own opposite is refused where the declaration is written rather than left for a shard to discover.

`locked`'s row is a consequence rather than a stipulation: every mutating mode refuses a locked target, so no transaction can hold a conflicting mode on one.

Determinism rules for the commutative modes: `delta` application order is canonical (transaction hash) and outcome-invariant; `reserve` feasibility is judged against committed balance minus reservations already held, ordered by transaction hash, and never counts in-flight deltas — so feasibility verdicts are identical on every replica regardless of scheduling. Reservation settle and release happen at finalization with the same ordering.

**The debit floor.** A `delta` decrement is unconditional in declaration — no feasibility precondition, nothing provisioned — but bounded at commit: each transaction's net movement per cell is judged in canonical order against committed balance plus its own credits minus every outstanding reservation, so a debit can never consume value a held reservation still covers. A debit past that floor aborts *its* transaction as an infeasibility-class loss ([04-execution-semantics.md](04-execution-semantics.md) §4) with fuel charged, and never a batch-level failure. Credits are unconditional. The floor is a *cell* property, not a mode's: an exclusive `write` can lower an amount cell below a reservation another transaction in the same conflict group still holds, and that reserver's settle then takes the identical infeasibility-class loss an uncovered debit takes. A cell that no longer covers its outstanding reservations is a lost race, never a ledger-invariant violation to escalate.

**A movement folds only where its cell lives.** A shard that does not own a key judges no movement on it, folds none into its own state, and settles no reservation against it — the owning shard does all three. What a non-owning shard keeps is the receipt entry: the movement is its outbound record, byte-identical to the one the owner derives. Folding a remote movement locally would fabricate a balance for a cell the shard holds nothing of, and would let a queued movement survive into a later transaction's receipt — both are cross-shard receipt divergence, and scoping the fold to ownership is what forecloses them.

## 3. Modes reshape provisioning

A provision needs to carry only what a counterpart must *read*: fresh-`read` values and the prior values of read-modify-`write` keys. A `delta` reads nothing; a `reserve`'s feasibility is judged at the owning shard; a `write` needs the prior value only where it reads one, and its presence requirement needs the leaf's *existence* — which the same provision carries, so every participant reaches the identical verdict on it rather than reading its own store for a leaf it may not hold. Cross-shard legs composed of commutative effects therefore provision nothing, their dependency sets shrink or empty, and a leg with no dependencies dispatches immediately — coupling reduction that falls out of the lattice alone ([08-host-integration.md](08-host-integration.md) §1).

## 4. Locked reads

A `locked` effect reads a substate the kernel has permanently locked: package code, creation-fixed instance configuration (a resource's divisibility and feature set), locked metadata, non-fungible field-mutability sets. Because no version of the target differs, the read needs no coherence and no proof: it takes no lock, defers nothing, conflicts with nothing, and makes its owner no participant — the one mode a shard can serve without joining the transaction (INV-VM-3). Verification is by content address, so any node resolves a locked read from any peer with no consensus round. This is what keeps inner-object hot paths shard-local: a vault's checks against its resource's immutable configuration add no shard to a transfer.

A read of *mutable* state is `read`: fresh, coherent, provisioned, its owner a participant. There is no third option — no mode reads mutable state without its owner in the transaction.

**Deferred: a staleness-windowed read of mutable state.** A version-pinned snapshot read carried as a client-supplied proof would let a transaction read a remote mutable cell — an oracle price — without making its owner a participant. It is deferred, not dropped: binding a signer-chosen value to a real attested root is a distributed problem in its own right, the window vocabulary (versions versus time) wants a real consumer to decide it, and the lattice already dissolves reader-versus-reader contention on hot cells. Its named consumer is the oracle feed; it returns with its root binding built and its window expressed in weighted time.

## 5. Range effects

Ordered collections ([03-objects-and-state.md](03-objects-and-state.md) §2) are accessed by **declared key interval**: a range over a collection's canonical key space is a static effect target like any point key, carrying a mode and an entry cap. Conflict checking is interval overlap, against both point and range effects. Scans, drains, paginated sweeps, and by-order queries — order books, leaderboards, non-fungible vault enumeration — become declarable: the returned *entries* depend on state, but the touched *key space* does not, which is all total-static access requires. Unbounded iteration stays restructured (the pagination-crank idiom); a range effect always carries its cap, and the cap itself is bounded at publish — it is the one part of a declaration that buys execution work rather than key space, so neither the footprint nor the conflict verdict prices it and a page is paid for in fuel instead ([05-runtime.md](05-runtime.md)).

Ranges are also **access-stable**: the declared interval stays valid whatever entries enter or leave it between signing and execution, so range-shaped patterns — order-book fills above all — do not pay the staleness tax that point-key patterns (liquidation races, routing) do. The tax lands on point-key races, not on books.

## 6. Enforcement

The kernel does not check accesses against a declared list; it **only materializes handles for the declared set**. The component's world imports state-access capabilities per declared key and mode; an undeclared access has no handle to call and traps. Traps, infeasible reservations, and a `locked` read of an unlocked target all land in the abort taxonomy of [04-execution-semantics.md](04-execution-semantics.md) — deterministic, identical on every replica. This is constructive enforcement with the trust inverted: nothing about safety depends on declarations being right (INV-VM-1). The compiler owes tightness, a contention and fee property; the gate owes soundness.

What that leaves open is the declaration itself. Handles bound execution to the declared set, and nothing in the shape of a set says whose cells are in it — so a signature declares only against its own instance's prefix, and a target naming any other is refused (INV-VM-16). The owner half of a key is written as `self` or derived under it; an argument, a configuration slot, a `for-each` binding and a literal are all somebody else's prefix. Publish refuses the expression so an author hears about it, and routing refuses the evaluated effect so no expression shape can be overlooked. An object's cells are reachable by calling it, never by naming them, which is what leaves a method's declared accessibility ([02-manifests-and-intents.md](02-manifests-and-intents.md)) as the only way in.

Test builds keep the claim honest continuously: the kernel's trace-subset oracle (`crates/kernel`) records every substate access and asserts `trace ⊆ declared` on every scenario, differential, and fuzz workload. A violation is a design-falsifying event, not a bug.

## 7. The routing function

One pure function, evaluable by any node — validator, RPC, wallet, gossip relay — with no state, as a fold over the manifest's nodes:

```
route(tx, metadata_cache) -> { participating shards,
                               per-shard (key, mode) sets,
                               per-node declared frames }
```

Consumed at gossip admission, mempool analysis, proposal selection, provision-set assembly, and fee estimation. Shard resolution (prefix → live shard) comes from the host's topology state, never from a peer. A wrong `route` output is impossible while metadata is immutable (INV-VM-2); a *loose* one costs the sender fees.

## 8. The transaction envelope

Wire-format decisions the effect model fixes:

- **The effect set is recomputed, never carried.** `route` is O(manifest) over immutable metadata, so every node derives the effect set itself; carrying it would add a carried-versus-computed mismatch class for no benefit. The envelope carries only the signing-time choices no node can derive: the signed `max_fee` and gas limit, and the fee payer.
- **Validity windows anchor on weighted time**, like everything consensus-visible.
- **A capped attachment.** The envelope carries an optional message — plaintext or encrypted to named recipients, size-capped — signed with the intent, priced as retention bytes ([04-execution-semantics.md](04-execution-semantics.md) §5).
- **No account nonces.** Replay protection is transaction-hash dedup with terminal tombstones, bounded by the weighted-time validity window. A nonce is an exclusive write on an account substate: it would serialize every account's transactions and forfeit exactly the concurrency `reserve` buys — multiple independent in-flight transactions per account, compatible because reservations commute.

## 9. Where a declaration comes from

An author writes one body. `#[blueprint]` over a module derives from it both the declaration routing reads and the component that executes it, so the two cannot disagree: the export's parameter list is a residue of the body rather than a second statement of it. What the derivation cannot do is infer a key the body computes from state — routing evaluates a declaration before execution and never reads state, so a key that arrives at execution time arrives too late. Keys are therefore *stated*; the SDK makes stating one look like ordinary Rust and does not pretend to guess it, and a body that reaches for a key it cannot declare is a compile error on the line that reaches.

The declaration is *run* rather than read off the source: a host build of the package evaluates it against the real evaluator, a `wasm32` build compiles the code, and the two are attached into one artifact. The command that does this (`cargo hyperscale`, `crates/cli`) is also the one that judges the result.

**One publish gate, reached from both ends.** Admission and the build run the same call over the same bytes (`crates/gate`), so a package that builds locally has passed exactly what the chain runs rather than a reimplementation that agrees until it does not. The verdict is a pure function of the artifact: it clears the deterministic profile ([05-runtime.md](05-runtime.md) §2), it carries canonical metadata within the bounds the vocabulary fixes, every method it declares is a function the component exports, and each method's argument binding agrees with that export's own type. A publish that cannot be admitted never enters a block, so nobody stores it and nobody pays for it.

**Marks about how a method ends are read off the code, never taken on trust.** A signature says whether a method can decline, and whether anything rules out a trap ([04-execution-semantics.md](04-execution-semantics.md) §4). The gate holds the first to the export's own type in both directions, and grants the second only by scanning the body the export actually runs — resolved through the component's wiring rather than by matching a name, since a core module may export whatever names it likes. The mark is what lets a caller commit without waiting to hear back, so it is the one claim in a package that a publisher cannot simply assert.

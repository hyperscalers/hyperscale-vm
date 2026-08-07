# The Hyperscale VM: overview

The Hyperscale VM is an execution engine built for a sharded BFT protocol whose safety story is determinism-by-declaration: routing, locking, provisioning, conflict verdicts, and fee assurance are all computed *before* execution, from committed content, identically on every replica. A conventional smart-contract engine is opaque to such a protocol — what a transaction touches is discovered by running it, so locks are coarse and exclusive, every participant must replay whole programs, and every property the protocol needs early arrives late. This engine inverts that: **access sets, ownership, access modes, commutativity, and authorization are type-level facts**, fixed by the signed transaction and content-addressed package metadata, checked at deploy and admission, and enforced at execution by construction.

The recurring design move: wherever a property the host protocol already enforces — determinism, attestation, immutability, static declaration — lets a mechanism be *deleted*, it is deleted rather than rebuilt better. Enforcement by construction over enforcement by check.

## What that buys, concretely

- **Any node can compute a transaction's full footprint without executing it.** One pure function, `route()` in `crates/effects`, folds over the manifest and returns the participating shards, the per-shard key-and-mode sets, and the static call graph (INV-VM-2). Mempools schedule on it, proposers budget on it, provision assembly reads it, wallets render it.
- **Undeclared access is unreachable, not filtered.** The kernel materializes state handles only for the declared effect set; an access outside it has no handle to call and traps deterministically (INV-VM-1). Nothing about safety depends on declarations being right — the compiler owes tightness, the gate owes soundness.
- **Concurrency is judged per substate, per mode.** Five access modes with a compatibility relation replace exclusive whole-object locks: reads share with reads, increments and reservations commute, reads of immutable state conflict with nothing at all ([01-effects-and-routing.md](01-effects-and-routing.md)).
- **Ownership is structural.** The owner is part of every substate's key, child addresses are computed rather than allocated, and placement is a property of the name (INV-VM-4) — no ownership walk, no contested claims, no re-parenting except by explicit move ([03-objects-and-state.md](03-objects-and-state.md)).
- **Cross-shard cost shrinks with the modes.** A provision carries only what a counterpart must read; commutative legs provision nothing and dispatch immediately ([07-host-integration.md](07-host-integration.md)).
- **Execution parallelizes without speculation.** Conflict groups derive from the declared effects, application order is canonical, and receipts are byte-identical across serial, parallel, and adversarially permuted schedules (INV-VM-14, [04-execution-semantics.md](04-execution-semantics.md)).

## Non-goals

- **Optimistic concurrency / speculative execution** — determinism-by-declaration is the foundation; commit-time reconciliation reintroduces the agreement problem declaration exists to avoid.
- **Compensation/sagas** — observable protocol-level intermediate states break atomicity; reservations are the accepted alternative. (Application-designed commit/claim protocols are not this.)
- **Kernel-level fund recovery or admin bailouts** — reintroduces the admin-key exploit class immutability exists to remove ([06-stdlib-and-upgrades.md](06-stdlib-and-upgrades.md)).
- **Native oracle machinery** — feeds are ordinary contracts; the mode lattice makes their readers share, and nothing more is owed.
- **Scrypto or EVM compatibility** — the effect-typed ABI is not expressible under either; no shim layer.
- **Multi-engine consensus** — one blessed engine version per protocol version; bit-identical agreement across independent engines is a non-goal ([05-runtime.md](05-runtime.md)).
- **General async contract-to-contract messaging** — cross-shard composition is atomic multi-shard transactions over declared state, not mailboxes.

## What to formally verify first

The register ([08-invariants.md](08-invariants.md)) enumerates the full property set; the critical core is small:

1. **Access truth** (INV-VM-1/2): execution cannot leave the declared set, and every honest node derives the same set.
2. **Value conservation** (INV-VM-6/7): per-resource supply and storage-bond accounting balance in every reachable state, including across shard splits and merges (with INV-VM-5).
3. **Fee assurance** (INV-VM-9/10/11): no shard works for a payer that cannot pay, and every engaged reservation resolves exactly once.
4. **Schedule invariance** (INV-VM-14): receipts are functions of committed content, never of execution timing.

Everything else either supports these or bounds resources.

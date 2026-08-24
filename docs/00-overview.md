# The Hyperscale VM: overview

The Hyperscale VM is an execution engine built for a sharded BFT protocol whose safety story is determinism-by-declaration: routing, locking, provisioning, conflict verdicts, and fee assurance are all computed *before* execution, from committed content, identically on every replica. A conventional smart-contract engine is opaque to such a protocol — what a transaction touches is discovered by running it, so locks are coarse and exclusive, every participant must replay whole programs, and every property the protocol needs early arrives late. This engine inverts that: **access sets, ownership, access modes, commutativity, and authorization are type-level facts**, fixed by the signed transaction and content-addressed package metadata, checked at deploy and admission, and enforced at execution by construction.

The recurring design move: wherever a property the host protocol already enforces — determinism, attestation, immutability, static declaration — lets a mechanism be *deleted*, it is deleted rather than rebuilt better. Enforcement by construction over enforcement by check.

## What that buys, concretely

- **Any node can compute a transaction's full footprint without executing it.** One pure function, `route()` in `crates/effects`, folds over the manifest and returns the participating shards, the per-shard key-and-mode sets, and each node's declared frame (INV-VM-ACCESS-2). Mempools schedule on it, proposers budget on it, provision assembly reads it, wallets render it.
- **Undeclared access is unreachable, not filtered.** The kernel materializes state handles only for the declared effect set; an access outside it has no handle to call and traps deterministically (INV-VM-ACCESS-1). Nothing about safety depends on declarations being right — the compiler owes tightness, the gate owes soundness.
- **Concurrency is judged per substate, per mode.** Five access modes with a compatibility relation replace exclusive whole-object locks: reads share with reads, increments and reservations commute, reads of immutable state conflict with nothing at all ([01-effects-and-routing.md](01-effects-and-routing.md)).
- **Ownership is structural.** The owner is part of every substate's key, child addresses are computed rather than allocated, and placement is a property of the name (INV-VM-OBJ-1) — no ownership walk, no contested claims, no re-parenting except by explicit move ([03-objects-and-state.md](03-objects-and-state.md)).
- **Cross-shard cost shrinks with the modes.** A provision carries only what a counterpart must read; commutative legs provision nothing and dispatch immediately ([08-host-integration.md](08-host-integration.md)).
- **Authority is presented, never ambient.** A gate mints a claim only after reading state that verifies it, and a node names exactly what it hands its callee — so there is no auth zone to leak through, no `msg.sender` to spoof, and no proof a caller can conjure ([06-authority.md](06-authority.md)).
- **Execution parallelizes without speculation.** Conflict groups derive from the declared effects, application order is canonical, and receipts are byte-identical across serial, parallel, and adversarially permuted schedules (INV-VM-RUN-1, [04-execution-semantics.md](04-execution-semantics.md)).

## The crate map

The workspace layers strictly; every arrow points down and nothing reaches around a layer.

| Layer | Crates | What lives there |
|---|---|---|
| Encoding | `hbor`, `hbor-macros` | The canonical codec (INV-VM-RUN-2) and its derives |
| Vocabulary | `types` | Addresses, effects, modes, outcomes, receipts, the math — every type two layers share |
| Boundary | `embed` | The engine seam: `KernelHost`, `GuestArg`, `Invoked`, the boundary charge table |
| Declaration | `effects` | Signatures, the access DSL, admission, `route()`, the metadata cache |
| Engines | `runtime` (blessed), `ref` (executable spec) | Each speaks `embed` and never `effects` |
| Kernel | `kernel` | Sessions, capabilities, the manifest walk, receipts, supply accounting |
| Gate | `gate` | The publish verdict, composed from the profile, the metadata codec, and the export judgment |
| Authoring | `sdk`, `sdk-macros`, `manifest-builder` | `#[blueprint]`, the tracer, the client tier |
| Tooling | `cli`, `stdlib`, `fixtures`, `testing`, `harness` | `cargo hyperscale`, the protocol packages, test guests, the author lanes, the differential harness |

Two rules the graph obeys: **engines never see effects** — what a declaration means is the kernel's and admission's business, and an engine is handed materialized handles with no idea what declared them; and **the kernel drives engines only through embed** — one seam, so the blessed engine and the executable spec are substitutable behind it.

## Non-goals

- **Optimistic concurrency / speculative execution** — determinism-by-declaration is the foundation; commit-time reconciliation reintroduces the agreement problem declaration exists to avoid.
- **Compensation/sagas** — observable protocol-level intermediate states break atomicity; reservations are the accepted alternative. (Application-designed commit/claim protocols are not this.)
- **Kernel-level fund recovery or admin bailouts** — reintroduces the admin-key exploit class immutability exists to remove ([07-stdlib-and-upgrades.md](07-stdlib-and-upgrades.md)).
- **Native oracle machinery** — feeds are ordinary contracts; the mode lattice makes their readers share, and nothing more is owed.
- **Scrypto or EVM compatibility** — the effect-typed ABI is not expressible under either; no shim layer.
- **Multi-engine consensus** — one blessed engine version per protocol version; bit-identical agreement across independent engines is a non-goal ([05-runtime.md](05-runtime.md)).
- **General async contract-to-contract messaging** — cross-shard composition is atomic multi-shard transactions over declared state, not mailboxes.

## What to formally verify first

The register ([09-invariants.md](09-invariants.md)) enumerates the full property set; the critical core is small:

1. **Access truth** (INV-VM-ACCESS-1/2): execution cannot leave the declared set, and every honest node derives the same set.
2. **Value conservation** (the whole `INV-VM-VALUE-*` family, with INV-VM-OBJ-2/3): per-resource supply and storage-bond accounting balance in every reachable state, including across shard splits and merges, and no transaction duplicates or loses value — neither in flight between them, nor in the cells it rests in, which are reached only through handles that move it.
3. **Fee assurance** (INV-VM-HOST-1/2/3): no shard works for a payer that cannot pay, and every engaged reservation resolves exactly once.
4. **Schedule invariance** (INV-VM-RUN-1): receipts are functions of committed content, never of execution timing.

Everything else either supports these or bounds resources.

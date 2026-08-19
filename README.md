# hyperscale-vm

> **Warning**: Work in progress. Do not use.

Rust implementation of the Hyperscale VM: an execution engine built for a sharded BFT protocol whose safety story is **determinism-by-declaration** — routing, locking, provisioning, conflict verdicts, and fee assurance are all computed *before* execution, from committed content, identically on every replica. Access sets, ownership, access modes, commutativity, and authorization are type-level facts, fixed by the signed transaction and content-addressed package metadata, checked at deploy and admission, and enforced at execution by construction.

**What makes it distinctive:**

- **Total static access.** One pure function, `route()`, folds over a transaction's manifest and returns the participating shards, the per-shard key-and-mode sets, and the static call graph — no execution, no state read. Mempools schedule on it, proposers budget on it, provision assembly reads it, wallets render it.
- **Enforcement by construction.** The kernel materializes state handles only for the declared effect set; an undeclared access has no handle to call and traps deterministically. Nothing about safety depends on declarations being right — the compiler owes tightness, the gate owes soundness.
- **Concurrency from a mode lattice.** Five access modes with a compatibility relation replace exclusive whole-object locks: reads share with reads, increments and reservations commute, locked reads conflict with nothing at all — so a thousand deposits to one vault are one parallel group, and cross-shard legs composed of commutative effects provision nothing.
- **Deterministic parallelism without speculation.** Conflict groups derive from the declared effects and application order is canonical: receipts are byte-identical across serial, parallel, and adversarially permuted execution schedules.
- **A frozen deterministic profile, executed twice.** A WASM Component Model host under an allowlisted subset — no floats, no threads, fuel-metered down to boundary copies — run by a version-pinned blessed engine (wasmtime) and an independently written reference interpreter, differentially tested against each other. Divergence is a release blocker, whichever side is wrong.

**[Architecture documentation → docs/](docs/README.md)** — the engine in a three-page overview, per-subsystem deep dives, and a consolidated invariant register (`INV-VM-*`) intended as the starting point for formal verification.

**[Upgrades and the determinism audit → upgrades.md](upgrades.md)** — how the engine pin, the profile, and admitted guest toolchains move, and the audit that gates each event.

## Crates

| Crate | Purpose |
|-------|---------|
| [`effects`](crates/effects) | Effect signatures and the manifest: the access DSL and its evaluator, the content-addressed metadata cache, the typed dataflow graph with admission, and `route()` |
| [`embed`](crates/embed) | The engine embedding seam: the kernel's host surface every runtime implements, and one assembled call |
| [`harness`](crates/harness) | Differential lanes, corpora, and guest fixtures — dev-only, never a dependency of a shipped crate |
| [`hbor`](crates/hbor) | The canonical encoding: schema-external, canonical at decode, natively merkleized |
| [`hbor-macros`](crates/hbor-macros) | Derive macros for HBOR encode, decode, and schema |
| [`kernel`](crates/kernel) | The object model and mode semantics: the substate store with access recording, structural ownership, the delta/reserve execution semantics, supply accumulators, and the trace-subset oracle |
| [`manifest-builder`](crates/manifest-builder) | Typed client-side manifest construction |
| [`ref`](crates/ref) | The reference interpreter of the profile: the executable spec, independently written, differentially tested against the blessed engine |
| [`runtime`](crates/runtime) | The blessed-engine embedding: wasmtime configuration, the deploy-time profile validator, the `hyperscale:kernel` world, fuel and canonical-ABI copy metering |
| [`sdk`](crates/sdk) | The guest-side authoring surface |
| [`sdk-macros`](crates/sdk-macros) | Proc macros behind the SDK's blueprint and state declarations |
| [`stdlib`](crates/stdlib) | The protocol's own packages — the account and the stake pool — as committed blobs, traced metadata, and the genesis flash |
| [`testing`](crates/testing) | The package author's chain: publish, seed, call, assert — a `cargo test` in a package crate, against the real kernel |
| [`types`](crates/types) | The transaction envelope, addresses, and the wire vocabulary shared with the host |

`guests/` holds the pinned-toolchain guest fixtures: the transfer fixture plus the minimal stdlib — account, constant-product pool, and order book — that the pattern corpus executes on both runtimes. The committed stdlib blobs are canonically Linux-built: roll them with `scripts/regenerate-stdlib.sh` (Docker, the same x86-64 Linux CI verifies on) and commit the result, not a local build from another OS.

Nothing here depends on the protocol workspace; hyperscale-rs consumes these crates as path dependencies through its `vm/` submodule.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

# Hyperscale VM documentation

Architecture documentation for the Hyperscale execution engine: the effect-typed VM that turns state access, ownership, access modes, and commutativity into type-level facts checked at deploy and admission rather than discovered at execution. These docs serve two consumers:

1. **Technical readers** who want the real design without reading the code — each doc is a self-contained narrative with light code anchoring (crate and type names, no line numbers).
2. **Formal verification** — critical properties are stated inline where they arise and consolidated with stable IDs in the invariant register.

## Reading order

Start with the overview; it tells the whole story in three pages and links down.

| Doc | Contents |
|---|---|
| [00-overview.md](00-overview.md) | The engine in miniature: the thesis, what static access buys a sharded host, the crate map, and the non-goals |
| [01-effects-and-routing.md](01-effects-and-routing.md) | Effect signatures, the access DSL, the mode lattice, locked reads, range effects, capability enforcement, `route()`, the transaction envelope, and where a declaration comes from — authoring, and the one publish gate |
| [02-manifests-and-intents.md](02-manifests-and-intents.md) | The typed dataflow manifest: nodes, edges, linearity, constraints — and subintents as separately-signed sub-graphs |
| [03-objects-and-state.md](03-objects-and-state.md) | Structural ownership, canonical addresses, substate layout, the storage bond, onboarding, the no-singleton rule, and value linearity and conservation |
| [04-execution-semantics.md](04-execution-semantics.md) | Deterministic parallel execution: conflict groups, canonical order, the transaction clock and randomness, the abort taxonomy, and the fee quantities |
| [05-runtime.md](05-runtime.md) | The Component Model host: the frozen deterministic profile, the blessed engine and the reference interpreter, the host surface, authentication, and the encodings |
| [06-authority.md](06-authority.md) | What a proof carries, thresholds over claims, the five method gates, presence at admission versus satisfaction at execution, and choosing between a badge and a stored rule |
| [07-stdlib-and-upgrades.md](07-stdlib-and-upgrades.md) | The two-tier package rule, the migration pattern, co-location, and the stdlib inventory |
| [08-host-integration.md](08-host-integration.md) | The contract between engine and host: read-set provisions, engagement evidence, cross-shard fee assurance, target authority, and work attestation |
| [09-invariants.md](09-invariants.md) | The consolidated register of the VM's properties with stable IDs (INV-VM-*) |

## Conventions

- **Invariant IDs** (`INV-VM-<n>`) are stable references. They appear inline in each doc where the property arises; the precise statements live once, in [09-invariants.md](09-invariants.md). Cite them rather than restating properties.
- **The suite boundary.** This suite owns the `INV-VM-*` family and everything about execution semantics, the runtime, and the object model. The host protocol — consensus, atomic cross-shard commitment, sharding, sync, economics — is documented in the hyperscale-rs repository's `docs/`, which owns every other invariant family (`INV-SHARD-*`, `INV-EXEC-*`, `INV-BEACON-*`, …). Where a property spans the boundary — fee assurance, target authority — it lives here, in [08-host-integration.md](08-host-integration.md), because it is a requirement the engine's design places on any host.
- **Code anchors** name crates and load-bearing types (for example `route()` in `crates/effects`, the trace-subset oracle in `crates/kernel`). They are entry points for a code dive, not line-precise references.
- The docs describe the engine as designed and built; deferred mechanisms are flagged explicitly where a design records them (for example the staleness-windowed read in [01-effects-and-routing.md](01-effects-and-routing.md) §4).
- The upgrade process — how the engine pin, the profile, and admitted toolchains move, and the determinism audit that gates each event — lives beside the code in [../upgrades.md](../upgrades.md).

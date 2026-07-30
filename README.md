# hyperscale-vm

The Hyperscale execution runtime, developed in isolation from the protocol workspace: a WASM Component Model host under a frozen deterministic profile, a reference interpreter beside it, and the differential harness proving them against each other.

- `crates/vm-effects` — effect signatures and the manifest: the access DSL and its evaluator, the content-addressed metadata cache, the typed dataflow graph with admission, and `route()`, the fold from a manifest to per-shard effect sets and the static call graph.
- `crates/vm-kernel` — the object model and mode semantics: the substate store with access recording, structural ownership, the delta/reserve execution semantics, supply accumulators, and the trace-subset oracle.
- `crates/vm-runtime` — the blessed-engine embedding: wasmtime configuration, the deploy-time profile validator, the `hyperscale:kernel` world, fuel and canonical-ABI copy metering.
- `crates/vm-ref` — the reference interpreter of the profile: the executable spec, independently written, differentially tested against the blessed engine.
- `crates/vm-harness` — differential lanes, corpora, and guest fixtures. Dev-only; never a dependency of the other two.

Isolation is a build fact: nothing here depends on the protocol workspace, and nothing there depends on this repo until the runtime integrates behind the executor seam.

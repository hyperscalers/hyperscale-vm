# hyperscale-vm

The Hyperscale execution runtime, developed in isolation from the protocol workspace: a WASM Component Model host under a frozen deterministic profile, a reference interpreter beside it, and the differential harness proving them against each other.

- `crates/vm-runtime` — the blessed-engine embedding: wasmtime configuration, the deploy-time profile validator, the `hyperscale:kernel` world, fuel and canonical-ABI copy metering.
- `crates/vm-ref` — the reference interpreter of the profile: the executable spec, independently written, differentially tested against the blessed engine.
- `crates/vm-harness` — differential lanes, corpora, and guest fixtures. Dev-only; never a dependency of the other two.

Isolation is a build fact: nothing here depends on the protocol workspace, and nothing there depends on this repo until the runtime integrates behind the executor seam.

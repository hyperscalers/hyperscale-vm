# The determinism-audit procedure

The checklist for admitting a new toolchain, a new engine candidate, or an
engine version bump. Every step is executable from this repository; a
divergence at any step is a release blocker, whichever side is wrong.

## For an engine version bump (or a new backend of the pinned engine)

1. **Pin review.** Update the exact version in the workspace manifest; the
   lockfile change is part of the review diff. An engine bump is a deliberate
   event — never dependency drift.
2. **Profile conformance.** `cargo test -p hyperscale-vm-runtime` — the
   rejection corpus and the kernel-world tests must pass unchanged. Any newly
   accepted construct is a finding: the profile is frozen, so the validator
   must still reject it regardless of what the engine now supports.
3. **The backend matrix.** `cargo test -p hyperscale-vm-harness --test
   spike_matrix -- --nocapture` — fuel support, component support, trap kinds,
   and cross-backend fuel identity per the recorded matrix. A backend gaining
   or losing a capability changes which differential lanes exist.
4. **All differential lanes.** `cargo test -p hyperscale-vm-harness` — core
   hand corpus, generated corpus, component lanes, the Rust guest, the
   rejection lane; outcomes, host state, access logs, **and fuel** must agree
   with `vm-ref`. A fuel divergence on a bump means the engine changed its
   accounting between versions: the spec schedule in `vm-ref` is then updated
   deliberately, in the same review, with the change called out — never
   silently absorbed.
5. **Compile bounds.** `cargo test --release -p hyperscale-vm-harness --test
   compile_bombs -- --ignored --nocapture` — at-bound compile times recorded
   and compared against the previous pin's numbers; a pathological regression
   on any bomb shape is a finding even inside the sanity ceiling.
6. **Cache invalidation.** A bump invalidates compiled-module caches; the
   epoch-gated rollout pre-warms them before the boundary.

## For a new guest toolchain

1. **Build the fixture set.** Port the transfer guest (or an equivalent
   exercising every kernel interface) to the candidate toolchain, pinned to an
   exact toolchain version.
2. **Artifact conformance.** The componentized output must clear
   `validate_component` as-is. Known obligations the toolchain must meet: an
   explicit linear-memory maximum (for Rust, one linker flag), no float
   instructions in emitted code, imports confined to `hyperscale:kernel/*`.
   A toolchain that cannot meet an obligation is inadmissible — the profile
   does not bend per toolchain.
3. **Differential execution.** Run the fixture under the blessed engine and
   `vm-ref` with identical hosts: outcomes, host state, and fuel must agree
   across the fixture's happy path, its trap path, and its boundary-copy
   sizes.
4. **Embedded-runtime review.** Any language runtime compiled into the guest
   (allocator, GC, scheduler) is part of the audit surface: it must be
   deterministic under the profile (no time, no randomness, no
   address-dependent behavior observable in outputs). This is the step that
   keeps a Go GC or an embedded JS engine out until someone does the work.

## For `vm-ref` changes

`vm-ref` is the executable spec: it changes only to track a deliberately
bumped engine pin or to fix a divergence the lanes found. Either way the
change lands with the failing lane case promoted into the permanent corpus.

## Divergence policy

- Outcome or state divergence between the blessed engine and `vm-ref`:
  release blocker; whichever implementation is wrong gets fixed, and the case
  joins the corpus.
- Fuel divergence: same, with one extra rule — the spec schedule
  (`vm-ref`'s `fuel_cost` plus the boundary supplement) is the consensus
  definition; the engine matching it is what the pin guarantees.
- Exhaustion is part of that: both runtimes test the budget at the three
  points the engine does — function entry, loop header, and the bulk-op
  byte charge — so out-of-fuel is a shared verdict, swept across the
  boundary by `differential_fuel`.
- A workstation fuzz finding is promoted by checking its seed into the
  relevant lane before the fix merges.

## Fuel at a trap is not a fee input

The engine does not flush its in-register fuel counter when a core trap
unwinds, so the fuel it reports at a division by zero is engine-defined
(`spike_trap_fuel` pins the behavior, and a change to it trips a test).
Nothing consumes that number: an aborted transaction is priced at its
class floor, never at fuel consumed, so the unflushed register has no
consensus reader. What does have one is the out-of-fuel *outcome*, and
that is exact on both sides.

## The parser is a second copy

The workspace's `wasmparser` is a different copy from the one bundled
inside the pinned engine. Both are the same version today, and a validity
disagreement between them would be deterministic — every node runs the
same workspace copy — but it would show up as an artifact that deploys and
then fails to compile. A version bump moves both together.

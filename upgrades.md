# Upgrades and the determinism audit

How the frozen parts of the runtime move: the upgrade process for the blessed engine, its backend, and the profile, and the admission process for new guest toolchains. The determinism audit below is the gate every one of those events must pass; each step is executable from this repository, and a divergence at any step is a release blocker, whichever side is wrong.

## Upgrade events and their process

Two kinds of event move frozen surface, and they ride different channels:

- **Protocol upgrades** — an engine version bump, a blessed-backend change, or any profile change (a limit, an allowlisted proposal, a canonical-ABI option). Consensus outcomes can move, so the change ships through the host's epoch-gated governance channel and activates at an epoch boundary, never mid-epoch.
- **Admission decisions** — a new guest toolchain. Nothing consensus-visible changes; the toolchain's artifacts are simply admissible once the audit passes and inadmissible before.

The sequence for a protocol upgrade:

1. **Audit first.** The full checklist for the event class below runs green before any pin lands.
2. **One reviewed diff.** The version pin in the workspace manifest, the lockfile change, and any deliberate `vm-ref` spec-schedule update land in the same review, with every schedule change called out — a fuel-accounting change absorbed silently is the failure mode the two-implementation discipline exists to catch.
3. **Schedule the boundary.** The activation epoch is fixed ahead through the governance channel, so every operator knows the flip before it happens.
4. **Pre-warm.** An engine bump invalidates compiled-module caches, and package immutability means no other invalidation event exists — so caches recompile in the epoch before the boundary, and the recompilation avalanche is scheduled away rather than survived.
5. **Flip at the boundary.** Both sides of the boundary are deterministic: blocks anchored before it execute under the old pin, at or after it under the new one.

## Audit: an engine version bump (or a new backend of the pinned engine)

1. **Pin review.** Update the exact version in the workspace manifest; the lockfile change is part of the review diff. An engine bump is a deliberate event — never dependency drift.
2. **Profile conformance.** `cargo test -p hyperscale-vm-runtime` — the rejection corpus and the kernel-world tests must pass unchanged. Any newly accepted construct is a finding: the profile is frozen, so the validator must still reject it regardless of what the engine now supports.
3. **The backend matrix.** `cargo test -p hyperscale-vm-harness --test spike_matrix -- --nocapture` — fuel support, component support, trap kinds, and cross-backend fuel identity per the recorded matrix. A backend gaining or losing a capability changes which differential lanes exist.
4. **All differential lanes.** `cargo test -p hyperscale-vm-harness` — core hand corpus, generated corpus, component lanes, the Rust guest, the rejection lane; outcomes, host state, access logs, **and fuel** must agree with `vm-ref`. A fuel divergence on a bump means the engine changed its accounting between versions: the spec schedule in `vm-ref` is then updated deliberately, in the same review, with the change called out — never silently absorbed.
5. **Compile bounds.** `cargo test --release -p hyperscale-vm-harness --test compile_bombs -- --ignored --nocapture` — at-bound compile times recorded and compared against the previous pin's numbers; a pathological regression on any bomb shape is a finding even inside the sanity ceiling.

## Audit: a new guest toolchain

1. **Build the fixture set.** Port the transfer guest (or an equivalent exercising every kernel interface) to the candidate toolchain, pinned to an exact toolchain version.
2. **Artifact conformance.** The componentized output must clear `validate_component` as-is. Known obligations the toolchain must meet: an explicit linear-memory maximum (for Rust, one linker flag), no float instructions in emitted code, imports confined to `hyperscale:kernel/*`. A toolchain that cannot meet an obligation is inadmissible — the profile does not bend per toolchain.
3. **Differential execution.** Run the fixture under the blessed engine and `vm-ref` with identical hosts: outcomes, host state, and fuel must agree across the fixture's happy path, its trap path, and its boundary-copy sizes.
4. **Embedded-runtime review.** Any language runtime compiled into the guest (allocator, GC, scheduler) is part of the audit surface: it must be deterministic under the profile (no time, no randomness, no address-dependent behavior observable in outputs). This is the step that keeps a Go GC or an embedded JS engine out until someone does the work.
5. **Acyclic prelude.** The toolchain's emitted code — not just the contract's — must leave the core call graph acyclic, or the deploy-time stack bound cannot be proven and the artifact is inadmissible. For Rust this is one obligation: build without panic-formatting machinery (`-Zbuild-std` with `panic=immediate-abort`), since `core::fmt` and `std::panicking` are the only things in a guest that recurse. Measured on the account guest: 15 back edges with the default prelude, none without it.

## The frame model is measured, not assumed

The deploy-time bound converts a function's slot count into native bytes, which is a codegen detail. `spike_frame_size` measures it — recurse to exhaustion, divide the stack budget by the depth reached — across every backend the matrix admits, and asserts the profile's model over-approximates what it observes. Cranelift costs 48 bytes plus 8 per slot; Winch 64 plus 8. The model charges 256 plus 32, a margin of at least four. A codegen change that erodes the margin fails the spike before it reaches consensus.

## `vm-ref` changes

`vm-ref` is the executable spec: it changes only to track a deliberately bumped engine pin or to fix a divergence the lanes found. Either way the change lands with the failing lane case promoted into the permanent corpus.

## Divergence policy

- Outcome or state divergence between the blessed engine and `vm-ref`: release blocker; whichever implementation is wrong gets fixed, and the case joins the corpus.
- Fuel divergence: same, with one extra rule — the spec schedule (`vm-ref`'s `fuel_cost` plus the boundary supplement) is the consensus definition; the engine matching it is what the pin guarantees.
- Exhaustion is part of that: both runtimes test the budget at the three points the engine does — function entry, loop header, and the bulk-op byte charge — so out-of-fuel is a shared verdict, swept across the boundary by `differential_fuel`.
- A workstation fuzz finding is promoted by checking its seed into the relevant lane before the fix merges. `fuzz/` holds the workstation lanes — `cargo fuzz run` with `admitted_is_executable` (admission implies executability), `session_trace_is_declared` (fuzzed call sequences through a kernel session on both runtimes, oracle asserted at finish), or `hbor_decode` — in its own workspace, so an ordinary build never touches it.

## Fuel at a trap is not a fee input

The engine does not flush its in-register fuel counter when a core trap unwinds, so the fuel it reports at a division by zero is engine-defined (`spike_trap_fuel` pins the behavior, and a change to it trips a test). Nothing consumes that number: an aborted transaction is priced by its abort class from declared quantities — the user-error class settles the declared limit, the other classes their floor — never at fuel consumed, so the unflushed register has no consensus reader. What does have one is the out-of-fuel *outcome*, and that is exact on both sides.

That is a constraint the crates now have to keep, not merely a fact about them. `Work::units` — the quantity `BatchOutcome::work` carries beside every receipt — is built to be agreed on across replicas and runtimes, and it is derived from fuel. So it takes the fuel term only on `Outcome::Completed`, where both runtimes agree exactly; every abort attests its declared footprint alone, which the verdict does not move. `Receipt::fuel` still reports whatever the engine reported, trap included: it is the diagnostic that makes the rule auditable, and keeping it out of the attested scalar is what lets it stay honest.

The rule sits in one place, `Work::attest`, and the work map is derived in one pass after the batch settles rather than threaded through the seven routes a receipt can take out of the executor — a missing term would not fail, it would under-report, and the apply-time flip from completed to infeasible is exactly the route most likely to be forgotten.

`attested_work` holds the rule by injecting the divergence rather than reproducing it: the same aborting outcome is run twice with the two fuel readings the runtimes would each give at a trap, and the attested scalar must match across them. That is the stronger lane, because `spike_trap_fuel` already pins what the engines do and what needs proving here is that the kernel is indifferent to it — under whatever the engines do next, not only today's pair.

## What the in-process determinism proptests do not prove

They compare `f(x)` with `f(x)` in one process, which cannot see the divergences that live between processes: hash iteration order under a per-process seed, a value derived from an address, a reading of the clock or the environment. The proptests are nonetheless sufficient today, and for a reason that is a property of the crates rather than of the tests — there is no carrier:

- No `SystemTime`, `Instant`, `std::env`, randomness, or pointer formatting anywhere in `vm-effects`, `vm-kernel`, `vm-ref`, or `vm-runtime`. The clock and the randomness a guest observes are host inputs the kernel is handed, never ambient ones it reads.
- Every consensus-path collection is `BTreeMap`/`BTreeSet`, ordered by key. The `HashMap`s in `vm-ref` are name-keyed lookup tables for decoding, and none of them is iterated into an output: the one iteration copies a module's export map into an instance's, keyed the same way.
- Floats never enter, so no NaN bit pattern can.

Every item is checkable by reading the crates, and the sufficiency argument fails the moment one stops holding. Adding an ambient source, or iterating a hash-ordered container into anything a receipt or a hash can see, is therefore not a local change: it makes a cross-process differential lane a prerequisite rather than an option.

## The parser is a second copy

The workspace's `wasmparser` is a different copy from the one bundled inside the pinned engine. Both are the same version today, and a validity disagreement between them would be deterministic — every node runs the same workspace copy — but it would show up as an artifact that deploys and then fails to compile. A version bump moves both together.

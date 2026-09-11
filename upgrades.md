# Upgrades and the determinism audit

How the frozen parts of the runtime move: the upgrade process for the blessed engine, its backend, the profile and the fuel schedule, and the admission process for new guest toolchains. The determinism audit below is the gate every one of those events must pass; each step is executable from this repository, and a divergence at any step is a release blocker, whichever side is wrong.

## Upgrade events and their process

Two kinds of event move frozen surface, and they ride different channels:

- **Protocol upgrades** — an engine version bump, a blessed-backend change, any profile change (a limit, an allowlisted proposal), or a change to the schedule the meter charges by. Consensus outcomes can move, so the change ships through the host's epoch-gated governance channel and activates at an epoch boundary, never mid-epoch.
- **Admission decisions** — a new guest toolchain. Nothing consensus-visible changes; the toolchain's artifacts are simply admissible once the audit passes and inadmissible before.

The sequence for a protocol upgrade:

1. **Audit first.** The full checklist for the event class below runs green before any pin lands.
2. **One reviewed diff.** The version pin in the workspace manifest and the lockfile change land in the same review. A schedule change lands as one edit to the meter's schedule and one to `vm-ref`'s restatement of it, in the same review, with the change called out — the lane that holds the two statements to each other fails on either alone, so a price cannot move silently.
3. **Schedule the boundary.** The activation epoch is fixed ahead through the governance channel, so every operator knows the flip before it happens.
4. **Pre-warm.** An engine bump invalidates compiled-module caches, and package immutability means no other invalidation event exists — so caches recompile in the epoch before the boundary, and the recompilation avalanche is scheduled away rather than survived. A schedule change re-judges every artifact's stack bound as well, since the bound is a fact about the instrumented code.
5. **Flip at the boundary.** Both sides of the boundary are deterministic: blocks anchored before it execute under the old pin, at or after it under the new one.

## Audit: an engine version bump (or a new backend of the pinned engine)

1. **Pin review.** Update the exact version in the workspace manifest; the lockfile change is part of the review diff. An engine bump is a deliberate event — never dependency drift.
2. **Profile conformance.** `cargo nextest run --release -p hyperscale-vm-runtime` — the rejection corpus, the module gate and the core-module tests must pass unchanged. Any newly accepted construct is a finding: the profile is frozen, so the validator must still reject it regardless of what the engine now supports.
3. **The backend matrix.** `cargo nextest run --release -p hyperscale-vm-harness --test spike_matrix --no-capture` — core execution, trap-kind fidelity and NaN bit patterns per backend, against the recorded matrix. A backend gaining or losing a capability changes which differential lanes exist.
4. **All differential lanes.** `cargo nextest run --release -p hyperscale-vm-harness` — the hand corpus, the generated corpus, the module, pointer and bucket lanes, the guest corpus, the rejection lane; outcomes, host state, access logs, **and fuel** must agree with `vm-ref`. The engine has no accounting of its own, so a fuel divergence on a bump is never a schedule to update: it is one side running the instrumented module wrongly, and it is fixed on that side.
5. **Compile bounds.** `cargo test --release -p hyperscale-vm-harness --test compile_bombs -- --ignored --nocapture` — at-bound compile times recorded and compared against the previous pin's numbers; a pathological regression on any bomb shape is a finding even inside the sanity ceiling.
6. **The frame model.** `spike_frame_size` must still hold (below); a codegen change that moves a frame's native size moves the deploy-time bound's premise.

## Audit: a new guest toolchain

1. **Build the fixture set.** Port the transfer guest (or an equivalent exercising every kernel interface) to the candidate toolchain, pinned to an exact toolchain version.
2. **Artifact conformance.** The emitted core module must clear `validate_module` as-is. Known obligations the toolchain must meet: an explicit linear-memory maximum (for Rust, one linker flag); no float instructions in emitted code; imports confined to `kernel/*`, each at the type the kernel defines; exactly one exported memory, named as the kernel reads it; no start section; and nothing under the meter's namespace or exported as `fuel`, which the pass reserves. A toolchain that cannot meet an obligation is inadmissible — the profile does not bend per toolchain.
3. **Differential execution.** Run the fixture under the blessed engine and `vm-ref` with identical hosts: outcomes, host state, and fuel must agree across the fixture's happy path, its trap path, and its boundary-copy sizes.
4. **Embedded-runtime review.** Any language runtime compiled into the guest (allocator, GC, scheduler) is part of the audit surface: it must be deterministic under the profile (no time, no randomness, no address-dependent behavior observable in outputs). This is the step that keeps a Go GC or an embedded JS engine out until someone does the work. The linker's memory layout is part of it: the workspace places the Rust shadow stack first and sizes it at half a page, so an overflow traps out of bounds instead of running into the heap and a guest declares one page rather than seventeen, and a toolchain's own defaults are read against the same two questions.
5. **Acyclic prelude.** The toolchain's emitted code — not just the contract's — must leave the core call graph acyclic, or the deploy-time stack bound cannot be proven and the artifact is inadmissible. For Rust this is one obligation: build without panic-formatting machinery (`-Zbuild-std` with `panic=immediate-abort`), since `core::fmt` and `std::panicking` are the only things in a guest that recurse. Measured on the account guest: 15 back edges with the default prelude, none without it.

## The frame model is measured, not assumed

The deploy-time bound converts a function's slot count into native bytes, which is a codegen detail. `spike_frame_size` measures it — recurse to exhaustion, divide the stack budget by the depth reached — across every backend the matrix admits, and asserts the profile's model over-approximates what it observes. The model charges 256 bytes per frame plus 32 per slot. A codegen change that erodes the margin fails the spike before it reaches consensus, and the constants are then re-derived from the new numbers rather than nudged.

## `vm-ref` changes

`vm-ref` is the executable spec: it changes only to fix a divergence the lanes found, or to restate a deliberately changed schedule in the same review as the meter's edit. Either way the change lands with the failing lane case promoted into the permanent corpus.

## Divergence policy

- Outcome or state divergence between the blessed engine and `vm-ref`: release blocker; whichever implementation is wrong gets fixed, and the case joins the corpus.
- Fuel divergence: same. The schedule is stated twice — the meter's pass charges by it, and `vm-ref`'s `fuel_cost` restates it sharing no constant — and `fuel_schedule` holds every block of an instrumented module to the sum of the two. The boundary supplement is one piece of code both engines call, so a divergence there is a divergence in the operands it was handed.
- Exhaustion is part of that: both engines run the same checks — a block paid for at its head, a bulk operator paying its bytes where it runs, a grow paying its pages, instantiation prepaid off the bytes — so out-of-fuel is a shared verdict, swept across the budgets around each boundary by `differential_fuel`.
- A workstation fuzz finding is promoted by checking its seed into the relevant lane before the fix merges. `fuzz/` holds the workstation lanes — `cargo fuzz run` with `admitted_is_executable` (admission implies executability), `session_trace_is_declared` (fuzzed call sequences through a kernel session on both runtimes, oracle asserted at finish), `hbor_decode`, or `consensus_decode` — in its own workspace, so an ordinary build never touches it.

## Fuel at a trap is exact, and still not a fee input

A metering block is paid for whole before it runs, so what the counter holds at any ending — a return, a trap, an exhaustion — is exact under one rule both engines share, and an exhaustion spends the whole budget. `Receipt::fuel` reports that figure, trap included.

The fee rule is a separate one. `Work::attest` takes the fuel term only on a completed execution; an abort attests its declared footprint alone, because what an aborted execution got through is not what it is charged for — a declaration is admitted, routed and locked in full whatever the verdict, and the user-error class settles the declared limit. The rule sits in one place, and the work map is derived in one pass after the batch settles rather than threaded through the seven routes a receipt can take out of the executor — a missing term would not fail, it would under-report, and the apply-time flip from completed to infeasible is exactly the route most likely to be forgotten.

## What the in-process determinism proptests do not prove

They compare `f(x)` with `f(x)` in one process, which cannot see the divergences that live between processes: hash iteration order under a per-process seed, a value derived from an address, a reading of the clock or the environment. The proptests are nonetheless sufficient today, and for a reason that is a property of the crates rather than of the tests — there is no carrier:

- No `SystemTime`, `Instant`, `std::env`, randomness, or pointer formatting anywhere in `vm-effects`, `vm-kernel`, `vm-meter`, `vm-ref`, or `vm-runtime`. The clock and the randomness a guest observes are host inputs the kernel is handed, never ambient ones it reads.
- Every consensus-path collection is `BTreeMap`/`BTreeSet`, ordered by key. The `HashMap`s in `vm-ref` are name-keyed lookup tables for decoding, and none of them is iterated into an output: the one iteration copies a module's export map into an instance's, keyed the same way.
- Floats never enter, so no NaN bit pattern can.

Every item is checkable by reading the crates, and the sufficiency argument fails the moment one stops holding. Adding an ambient source, or iterating a hash-ordered container into anything a receipt or a hash can see, is therefore not a local change: it makes a cross-process differential lane a prerequisite rather than an option.

## The parser is a second copy

The workspace's `wasmparser` — and the `wasm-encoder` the meter's pass writes through — is a different copy from the one bundled inside the pinned engine. Both are the same version today, and a validity disagreement between them would be deterministic — every node runs the same workspace copy — but it would show up as an artifact that deploys and then fails to compile. A version bump moves all of them together.
